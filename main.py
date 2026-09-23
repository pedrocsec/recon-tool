import importlib.util
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from modules.crtsh import enumerar_subdominios
from modules.dns import consultar_dns
from modules.portscan import scan_ports
from modules.techdetect import analisar_http
from modules.display import mostrar_resultado
from modules.intelligence import analyze_result, print_intelligence

def carregar_modulo_cve():
    caminho = Path(__file__).with_name("cve_correlation_4.1_updated.py")
    spec = importlib.util.spec_from_file_location(
        "cve_correlation_4_1_updated",
        caminho
    )
    if spec is None or spec.loader is None:
        raise ImportError(
            f"Não foi possível carregar o módulo CVE: {caminho}"
        )
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


modulo_cve = carregar_modulo_cve()
correlacionar_resultado = modulo_cve.correlacionar_resultado
print_cve_correlation = modulo_cve.print_cve_correlation


VERSION = "4.1.3"
REPORT_FILE = "resultado.json"


def linha():
    print("=" * 58)


def titulo(texto):
    print()
    linha()
    print(f"              {texto}")
    linha()


def agora():
    return datetime.now().isoformat()


def normalizar_lista(valor):
    """
    Garante que um valor seja sempre uma lista.
    """
    if valor is None:
        return []

    if isinstance(valor, list):
        return valor

    return [valor]


def normalizar_tecnologias(tecnologias):
    """
    Converte diferentes formatos de tecnologia
    para o formato esperado pelo restante do projeto.
    """

    resultado = []

    for tecnologia in normalizar_lista(tecnologias):

        if isinstance(tecnologia, str):
            resultado.append({
                "name": tecnologia,
                "version": None,
                "source": "http_headers",
                "evidence": ""
            })

        elif isinstance(tecnologia, dict):

            nome = tecnologia.get(
                "name",
                tecnologia.get(
                    "technology",
                    tecnologia.get(
                        "tech",
                        "Tecnologia desconhecida"
                    )
                )
            )

            resultado.append({
                "name": nome,
                "version": tecnologia.get("version"),
                "source": tecnologia.get(
                    "source",
                    "http_headers"
                ),
                "evidence": tecnologia.get(
                    "evidence",
                    ""
                )
            })

    return resultado


def extrair_tecnologias(dados_http):
    """
    Extrai tecnologias do resultado do analisador HTTP.

    O techdetect pode retornar:
        "technologies": ["Cloudflare"]

    ou:
        "technologies": [
            {
                "name": "Cloudflare"
            }
        ]

    ou tecnologias separadas por protocolo.
    """

    tecnologias = []

    if not isinstance(dados_http, dict):
        return tecnologias

    # Caso padrão
    tecnologias.extend(
        normalizar_tecnologias(
            dados_http.get("technologies", [])
        )
    )

    # Caso existam tecnologias dentro de HTTP/HTTPS
    for protocolo in ("http", "https"):

        dados = dados_http.get(protocolo)

        if not isinstance(dados, dict):
            continue

        tecnologias.extend(
            normalizar_tecnologias(
                dados.get("technologies", [])
            )
        )

    # Remove duplicadas
    unicas = []
    chaves = set()

    for tecnologia in tecnologias:

        chave = (
            tecnologia.get("name"),
            tecnologia.get("version")
        )

        if chave in chaves:
            continue

        chaves.add(chave)
        unicas.append(tecnologia)

    return unicas


def construir_web_data(portas):
    """
    Converte:

        ports -> [
            {
                "port": 80,
                "http": {...}
            }
        ]

    para:

        web -> {
            "80": {
                "http": {...}
            }
        }

    Esse é o formato esperado pelo intelligence.py.
    """

    web = {}

    for porta in portas:

        if not isinstance(porta, dict):
            continue

        numero = porta.get("port")

        if numero is None:
            continue

        dados_http = porta.get("http")

        if not isinstance(dados_http, dict):
            continue

        # Formato atual do techdetect.analisar_http():
        # { "http": {...}, "https": {...} }
        protocolos_aninhados = {}

        for protocolo in ("http", "https"):

            dados = dados_http.get(protocolo)

            if isinstance(dados, dict):
                protocolos_aninhados[protocolo] = dados

        if protocolos_aninhados:

            web[str(numero)] = protocolos_aninhados
            continue

        # Formato antigo/plano:
        # { "protocol": "...", "status_code": ... }
        protocolo = dados_http.get(
            "protocol"
        )

        if protocolo not in ("http", "https"):

            service = dados_http.get(
                "service"
            )

            if service == "https":
                protocolo = "https"

            elif service == "http":
                protocolo = "http"

            else:
                # Não conseguimos afirmar o protocolo.
                # Mantemos como HTTP apenas se houver
                # status HTTP válido.
                if dados_http.get("status_code") is not None:
                    protocolo = "http"
                else:
                    continue

        web[str(numero)] = {
            protocolo: dados_http
        }

    return web


def enriquecer_porta(porta, host):
    """
    Executa o analisador HTTP/HTTPS para uma porta aberta
    e mantém o resultado dentro da própria porta.

    Isso preserva a estrutura usada pelo display.py.
    """

    numero = porta.get("port")

    if numero is None:
        return porta

    try:

        resultado_http = analisar_http(
            host,
            numero
        )

        if isinstance(resultado_http, dict):

            # Caso o módulo já retorne diretamente
            # um resultado HTTP válido.
            porta["http"] = resultado_http

    except Exception as erro:

        porta["http"] = {
            "service": "unknown",
            "error": str(erro),
            "protocol": "unknown",
            "reachable": False
        }

    return porta


def preparar_host(
    hostname,
    ip_info,
    status,
    portas
):
    """
    Monta a estrutura definitiva de um host.
    """

    portas = normalizar_lista(portas)

    tecnologias = []

    portas_processadas = []

    for porta in portas:

        if not isinstance(porta, dict):
            continue

        portas_processadas.append(
            porta
        )

        http = porta.get("http")

        if isinstance(http, dict):

            tecnologias.extend(
                extrair_tecnologias(http)
            )

    # Remove tecnologias duplicadas
    tecnologias_finais = []
    chaves = set()

    for tecnologia in tecnologias:

        chave = (
            tecnologia.get("name"),
            tecnologia.get("version")
        )

        if chave in chaves:
            continue

        chaves.add(chave)
        tecnologias_finais.append(
            tecnologia
        )

    web = construir_web_data(
        portas_processadas
    )

    return {
        "ip": ip_info,
        "status": status,
        "ports": portas_processadas,
        "web": web,
        "technologies": tecnologias_finais,
        "cves": []
    }


def executar_scan(target):
    """
    Executa o recon completo.
    """

    target = str(target).strip().lower().rstrip(".")

    inicio = time.time()
    started_at = agora()

    print()
    linha()
    print(
        f"              🔎 RECON TOOL {VERSION}"
    )
    linha()

    print()
    print(f"[+] Alvo: {target}")
    print("[+] Iniciando enumeração...")
    print()

    # =========================================================
    # ENUMERAÇÃO
    # =========================================================

    try:

        subdominios = enumerar_subdominios(
            target
        )

    except Exception as erro:

        print(
            f"[-] Falha na enumeração: {erro}"
        )

        subdominios = []

    # Normaliza e deduplica os nomes retornados pelo crt.sh.
    nomes = []
    for nome in normalizar_lista(subdominios):
        if not isinstance(nome, str):
            continue
        nome = nome.strip().lower().rstrip(".")
        if not nome:
            continue
        if nome == target or nome.endswith("." + target):
            nomes.append(nome)

    # O domínio raiz é o alvo; subdominios contém somente hosts abaixo dele.
    subdominios = sorted(set(nomes) - {target})
    hosts_para_analisar = [target] + subdominios

    print(
        f"[+] Subdomínios encontrados: {len(subdominios)}"
    )
    print(
        f"[+] Total de hosts encontrados: "
        f"{len(hosts_para_analisar)}"
    )

    # =========================================================
    # RESULTADO BASE
    # =========================================================

    resultado = {
        "target": target,

        "enumeration": {
            "source": "crt.sh",
            "subdomains": subdominios
        },

        "hosts": {},

        "scan": {
            "started_at": started_at
        },

        "summary": {}
    }

    # =========================================================
    # ANÁLISE DOS HOSTS
    # =========================================================

    for host in hosts_para_analisar:

        print()
        print("-" * 58)
        print(
            f"[+] Analisando: {host}"
        )
        print("-" * 58)

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        ip_info = consultar_dns(
            host
        )

        if not ip_info or not (
            ip_info.get("ipv4") or
            ip_info.get("ipv6")
        ):

            print(
                "[-] DNS não resolveu."
            )

            resultado["hosts"][host] = {
                "ip": None,
                "status": "unresolved",
                "ports": [],
                "web": {},
                "technologies": [],
                "cves": []
            }

            continue

        ipv4 = ip_info.get(
            "ipv4",
            []
        )

        ipv6 = ip_info.get(
            "ipv6",
            []
        )

        if ipv4:

            print(
                "[+] IPv4: "
                + ", ".join(ipv4)
            )

        if ipv6:

            print(
                "[+] IPv6: "
                + ", ".join(ipv6)
            )

        # -----------------------------------------------------
        # PORT SCAN
        # -----------------------------------------------------

        print(
            "[+] Executando port scan..."
        )

        try:

            portas = scan_ports(
                host
            )

        except TypeError:

            # Compatibilidade caso a função
            # espere IP em vez de hostname.
            try:

                portas = scan_ports(
                    ipv4[0]
                    if ipv4
                    else host
                )

            except Exception as erro:

                print(
                    f"[-] Falha no port scan: "
                    f"{erro}"
                )

                portas = []

        except Exception as erro:

            print(
                f"[-] Falha no port scan: "
                f"{erro}"
            )

            portas = []

        portas = normalizar_lista(
            portas
        )

        portas_abertas = []

        for porta in portas:

            if not isinstance(
                porta,
                dict
            ):
                continue

            if porta.get("status") == "open":

                portas_abertas.append(
                    porta
                )

        print(
            f"[+] Portas abertas: "
            f"{len(portas_abertas)}"
        )

        # -----------------------------------------------------
        # HTTP / HTTPS
        # -----------------------------------------------------

        for porta in portas_abertas:

            numero = porta.get(
                "port"
            )

            print(
                f"[+] Analisando serviço: "
                f"{host}:{numero}"
            )

            enriquecer_porta(
                porta,
                host
            )

        # -----------------------------------------------------
        # HOST FINAL
        # -----------------------------------------------------

        resultado["hosts"][host] = preparar_host(
            hostname=host,
            ip_info=ip_info,
            status="resolved",
            portas=portas_abertas
        )

    # =========================================================
    # RESUMO
    # =========================================================

    finished_at = agora()
    duration = time.time() - inicio

    hosts = resultado["hosts"]

    resolved_hosts = sum(
        1
        for dados in hosts.values()
        if dados.get("status") == "resolved"
    )

    unresolved_hosts = sum(
        1
        for dados in hosts.values()
        if dados.get("status") == "unresolved"
    )

    total_open_ports = sum(
        len(
            [
                porta
                for porta in dados.get(
                    "ports",
                    []
                )
                if porta.get("status") == "open"
            ]
        )
        for dados in hosts.values()
    )

    total_technologies = sum(
        len(
            dados.get(
                "technologies",
                []
            )
        )
        for dados in hosts.values()
    )

    resultado["scan"].update({
        "finished_at": finished_at,
        "duration_seconds": duration
    })

    resultado["summary"] = {
        "total_hosts": len(hosts),
        "resolved_hosts": resolved_hosts,
        "unresolved_hosts": unresolved_hosts,
        "total_open_ports": total_open_ports,
        "total_technologies": total_technologies,
        "total_web_services": 0,
        "total_web_observations": 0
    }

    # =========================================================
    # INTELLIGENCE
    # =========================================================

    print(
        "[+] Executando RECON INTELLIGENCE..."
    )

    try:

        analysis = analyze_result(
            resultado
        )

        resultado["intelligence"] = analysis

        exposure = analysis.get("exposure", {})
        resultado["summary"]["total_web_services"] = exposure.get(
            "web_services", 0
        )
        resultado["summary"]["total_web_observations"] = exposure.get(
            "web_observations", 0
        )

        print_intelligence(
            analysis
        )

    except Exception as erro:

        print(
            f"[-] Falha na RECON INTELLIGENCE: "
            f"{erro}"
        )

        resultado["intelligence"] = {
            "error": str(erro)
        }

    # =========================================================
    # RECON CVE CORRELATION 4.1.3
    # =========================================================

    print()
    print("[+] Executando RECON CVE CORRELATION...")

    try:
        cve_analysis = correlacionar_resultado(
            resultado
        )

        resultado["cve_correlation"] = cve_analysis

        resultado["summary"]["total_cves_possible"] = cve_analysis.get(
            "cves_possiveis_total",
            0
        )
        resultado["summary"]["cve_hosts"] = cve_analysis.get(
            "hosts_com_cves_possiveis",
            0
        )
        resultado["summary"]["cve_technologies_processed"] = cve_analysis.get(
            "tecnologias_processadas",
            0
        )
        resultado["summary"]["cve_cpes_consulted"] = cve_analysis.get(
            "cpes_consultados",
            0
        )
        resultado["summary"]["cve_cache_hits"] = cve_analysis.get(
            "cache_hits",
            0
        )

        hosts_cve = cve_analysis.get("hosts", {})

        if isinstance(hosts_cve, dict):
            for host, dados_cve in hosts_cve.items():
                if host not in resultado["hosts"]:
                    continue

                if not isinstance(dados_cve, dict):
                    continue

                resultado["hosts"][host]["cves"] = dados_cve.get(
                    "cves_possiveis",
                    []
                )

        print_cve_correlation(
            cve_analysis
        )

    except Exception as erro:
        print(
            f"[-] Falha na RECON CVE CORRELATION: {erro}"
        )

        resultado["cve_correlation"] = {
            "version": "4.1.3",
            "error": str(erro),
            "cves_possiveis_total": 0,
            "hosts_com_cves_possiveis": 0
        }

        resultado["summary"]["total_cves_possible"] = 0
        resultado["summary"]["cve_hosts"] = 0

    # =========================================================
    # SALVAR JSON
    # =========================================================

    try:

        with open(
            REPORT_FILE,
            "w",
            encoding="utf-8"
        ) as arquivo:

            json.dump(
                resultado,
                arquivo,
                indent=4,
                ensure_ascii=False
            )

    except Exception as erro:

        print()
        print(
            f"[-] Erro ao salvar "
            f"{REPORT_FILE}: {erro}"
        )

    # =========================================================
    # RESULTADO FINAL
    # =========================================================

    mostrar_resultado(
        resultado
    )

    print()
    linha()
    print(
        "[+] Recon finalizado."
    )
    linha()

    return resultado


def main():

    # ---------------------------------------------------------
    # Argumento opcional:
    #
    # python3 main.py example.com
    #
    # Se nenhum argumento for fornecido,
    # usamos example.com para teste.
    # ---------------------------------------------------------

    if len(sys.argv) > 1:

        target = sys.argv[1].strip()

    else:

        target = "example.com"

    if not target:

        print(
            "[-] Alvo inválido."
        )

        sys.exit(1)

    executar_scan(
        target
    )


if __name__ == "__main__":
    main()