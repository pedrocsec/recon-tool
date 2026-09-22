import ipaddress
import re
import time
import requests


CRT_SH_URL = "https://crt.sh/"

TIMEOUT = 10
MAX_TENTATIVAS = 3

USER_AGENT = (
    "Mozilla/5.0 "
    "(Macintosh; Intel Mac OS X) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/120 Safari/537.36"
)

# Hostname válido (labels DNS simples, sem escapes literais).
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$"
)


def normalizar_dominio(dominio):
    """
    Remove protocolo, caminhos, espaços e escapes literais.
    """
    if dominio is None:
        return ""

    dominio = str(dominio).strip().lower()

    # Escapes literais vindos de JSON/regex (ex.: www\\.example.com)
    dominio = dominio.replace("\\.", ".")
    dominio = dominio.replace("\\*", "*")
    dominio = dominio.replace("\\", "")

    dominio = dominio.replace("https://", "")
    dominio = dominio.replace("http://", "")

    dominio = dominio.split("/")[0]
    dominio = dominio.split(":")[0]
    dominio = dominio.split("?")[0]
    dominio = dominio.split("#")[0]

    dominio = dominio.strip().strip(".")

    if dominio.startswith("*."):
        dominio = dominio[2:]

    return dominio


def hostname_valido(hostname, dominio_base):
    """
    Valida se o hostname é utilizável e pertence ao domínio alvo.
    """
    if not hostname:
        return False

    if not HOSTNAME_RE.match(hostname):
        return False

    if hostname == dominio_base:
        return True

    return hostname.endswith("." + dominio_base)


def alvo_local(dominio):
    """Identifica localhost e endereços IP locais/privados."""
    valor = normalizar_dominio(dominio)

    if not valor:
        return False

    if (
        valor == "localhost"
        or valor.endswith(".localhost")
        or valor == "localhost.localdomain"
    ):
        return True

    try:
        endereco = ipaddress.ip_address(valor)
    except ValueError:
        return False

    return (
        endereco.is_loopback
        or endereco.is_private
        or endereco.is_link_local
    )


def consultar_crtsh(dominio):
    """
    Consulta certificados públicos do domínio através do crt.sh.

    Uma única sequência de tentativas por execução.
    Retry apenas em falha transitória.
    """
    url = CRT_SH_URL

    params = {
        "q": f"%.{dominio}",
        "output": "json",
    }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    ultimo_erro = None

    for tentativa in range(1, MAX_TENTATIVAS + 1):
        print(
            f"[+] Consultando crt.sh "
            f"(tentativa {tentativa}/{MAX_TENTATIVAS})..."
        )

        try:
            resposta = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=TIMEOUT,
            )

            if resposta.status_code == 200:
                try:
                    dados = resposta.json()
                except ValueError:
                    raise RuntimeError(
                        "crt.sh retornou uma resposta que "
                        "não é JSON válido."
                    )

                return dados

            ultimo_erro = (
                f"crt.sh retornou HTTP {resposta.status_code}"
            )
            print(f"[-] Erro ao consultar crt.sh: {ultimo_erro}")

        except requests.Timeout:
            ultimo_erro = "Timeout ao consultar crt.sh"
            print(
                "[-] Erro ao consultar crt.sh: "
                "tempo limite excedido."
            )

        except requests.ConnectionError as erro:
            ultimo_erro = f"Falha de conexão com crt.sh: {erro}"
            print("[-] Erro de conexão com crt.sh.")

        except requests.RequestException as erro:
            ultimo_erro = str(erro)
            print(f"[-] Erro ao consultar crt.sh: {erro}")

        except RuntimeError as erro:
            ultimo_erro = str(erro)
            print(f"[-] Erro ao processar crt.sh: {erro}")

        if tentativa < MAX_TENTATIVAS:
            print(
                "[+] Aguardando 2s antes de "
                "tentar novamente..."
            )
            time.sleep(2)

    print(
        "[-] Não foi possível consultar o crt.sh "
        "após todas as tentativas."
    )

    if ultimo_erro:
        print(f"[-] Último erro: {ultimo_erro}")

    return None


def extrair_subdominios(dados, dominio):
    """
    Extrai e normaliza os nomes encontrados nos certificados.
    Remove duplicatas e hostnames inválidos/escapados.
    """
    encontrados = set()
    dominio = normalizar_dominio(dominio)

    if not dados:
        if dominio:
            encontrados.add(dominio)
        return sorted(encontrados)

    for certificado in dados:
        if not isinstance(certificado, dict):
            continue

        nome = certificado.get("name_value", "")

        if not nome:
            continue

        for linha in str(nome).splitlines():
            linha = normalizar_dominio(linha)

            if not linha:
                continue

            if hostname_valido(linha, dominio):
                encontrados.add(linha)

    if dominio:
        encontrados.add(dominio)

    return sorted(encontrados)


def fallback_basico(dominio):
    """
    Fallback simples caso o crt.sh esteja indisponível.

    Não tenta substituir a enumeração completa.
    Apenas garante que o alvo principal continue
    sendo analisado, sem duplicações artificiais.
    """
    dominio = normalizar_dominio(dominio)

    print()
    print("[!] Fallback de enumeração ativado.")
    print("[!] O crt.sh está indisponível.")
    print("[+] Mantendo o domínio principal para análise:")
    print(f"    └─ {dominio}")

    return [dominio] if dominio else []


def enumerar_subdominios(dominio):
    """
    Enumera subdomínios através do crt.sh (uma chamada lógica).

    Caso o serviço esteja indisponível, utiliza fallback básico.
    """
    dominio = normalizar_dominio(dominio)

    if not dominio:
        return []

    # crt.sh consulta certificados públicos. Para alvos locais/IPs,
    # consultar a CA pública não produz enumeração útil e pode gerar
    # falsos ativos. Mantemos somente o alvo principal.
    if alvo_local(dominio):
        print("[+] Alvo local detectado; pulando consulta ao crt.sh.")
        print(f"[+] Mantendo somente o alvo: {dominio}")
        return [dominio]

    dados = consultar_crtsh(dominio)

    if dados is None:
        return fallback_basico(dominio)

    subdominios = extrair_subdominios(dados, dominio)

    print(f"[+] Subdomínios encontrados: {len(subdominios)}")

    return subdominios
