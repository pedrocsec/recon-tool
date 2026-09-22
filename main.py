import json
import sys
import time
from datetime import datetime

from modules.crtsh import enumerar_subdominios
from modules.portscan import scan_ports
from modules.techdetect import (
    analisar_http,
    identificar_tecnologias,
)
from modules.display import mostrar_resultado
from modules.intelligence import analyze_result, print_intelligence

# =========================================================
# CVE CORRELATION 4.1
# =========================================================

from modules.cve_correlation import (
    correlacionar_resultado,
    print_cve_correlation,
)

# =========================================================
# RISK SCORE 4.1
# =========================================================

from modules.risk_score import (
    analisar_risco,
    gerar_relatorio_markdown,
)


# =========================================================
# CONFIGURAÇÃO
# =========================================================

VERSION = "4.1.2"

REPORT_FILE = "resultado.json"

RISK_REPORT_FILE = "risk_report.md"


# =========================================================
# UTILITÁRIOS
# =========================================================

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


# =========================================================
# TECNOLOGIAS
# =========================================================

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

    O analisador pode entregar tecnologias prontas em
    ``technologies``. Algumas detecções, porém, dependem diretamente
    dos headers, HTML e título. Quando esses dados existem, a mesma
    função de detecção é executada aqui para garantir que a tecnologia
    detectada entre no pipeline principal e, consequentemente, na
    correlação de CVEs.
    """

    tecnologias = []

    if not isinstance(dados_http, dict):
        return tecnologias

    # 1. Tecnologias já produzidas pelo analisador HTTP.
    tecnologias.extend(
        normalizar_tecnologias(
            dados_http.get(
                "technologies",
                []
            )
        )
    )

    # 2. Detecção complementar usando headers/html/title.
    def detectar(dados):

        if not isinstance(dados, dict):
            return

        headers = dados.get("headers", {})

        if not isinstance(headers, dict):
            headers = {}

        html = dados.get("html", "")
        if not isinstance(html, str):
            html = ""

        title = dados.get("title", "")
        if not isinstance(title, str):
            title = ""

        try:
            detectadas = identificar_tecnologias(
                headers,
                html,
                title
            )

            tecnologias.extend(
                normalizar_tecnologias(
                    detectadas
                )
            )

        except Exception:
            # Uma falha na detecção complementar não interrompe
            # o restante do recon.
            pass

    detectar(dados_http)

    # 3. Protocolos HTTP/HTTPS aninhados.
    for protocolo in ("http", "https"):

        dados = dados_http.get(protocolo)

        if not isinstance(dados, dict):
            continue

        tecnologias.extend(
            normalizar_tecnologias(
                dados.get(
                    "technologies",
                    []
                )
            )
        )

        detectar(dados)

    # 4. Remove duplicadas.
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


# =========================================================
# WEB DATA
# =========================================================

def construir_web_data(portas):
    """
    Converte os dados das portas para o formato
    utilizado pelo intelligence.py.
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

        protocolos_aninhados = {}

        for protocolo in ("http", "https"):

            dados = dados_http.get(protocolo)

            if isinstance(dados, dict):
                protocolos_aninhados[protocolo] = dados

        if protocolos_aninhados:

            web[str(numero)] = protocolos_aninhados

            continue

        protocolo = dados_http.get(
            "protocol"
        )

        if protocolo not in (
            "http",
            "https"
        ):

            service = dados_http.get(
                "service"
            )

            if service == "https":

                protocolo = "https"

            elif service == "http":

                protocolo = "http"

            else:

                if dados_http.get(
                    "status_code"
                ) is not None:

                    protocolo = "http"

                else:

                    continue

        web[str(numero)] = {
            protocolo: dados_http
        }

    return web


# =========================================================
# HTTP / HTTPS
# =========================================================

def enriquecer_porta(porta, host):
    """
    Executa análise HTTP/HTTPS para uma porta aberta.
    """

    numero = porta.get("port")

    if numero is None:
        return porta

    try:

        resultado_http = analisar_http(
            host,
            numero
        )

        if isinstance(
            resultado_http,
            dict
        ):

            porta["http"] = resultado_http

    except Exception as erro:

        porta["http"] = {
            "service": "unknown",
            "error": str(erro),
            "protocol": "unknown",
            "reachable": False
        }

    return porta


# =========================================================
# HOST
# =========================================================

def preparar_host(
    hostname,
    ip_info,
    status,
    portas
):

    portas = normalizar_lista(
        portas
    )

    tecnologias = []

    portas_processadas = []

    for porta in portas:

        if not isinstance(
            porta,
            dict
        ):
            continue

        portas_processadas.append(
            porta
        )

        http = porta.get(
            "http"
        )

        if isinstance(
            http,
            dict
        ):

            tecnologias.extend(
                extrair_tecnologias(
                    http
                )
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


# =========================================================
# DNS
# =========================================================

def resolver_host(host):
    """
    Resolve IPv4 e IPv6.
    """

    try:

        import socket

        infos = socket.getaddrinfo(
            host,
            None
        )

        ipv4 = []

        ipv6 = []

        for info in infos:

            endereco = info[4][0]

            if ":" in endereco:

                if endereco not in ipv6:

                    ipv6.append(
                        endereco
                    )

            else:

                if endereco not in ipv4:

                    ipv4.append(
                        endereco
                    )

        if not ipv4 and not ipv6:
            return None

        return {
            "ipv4": ipv4,
            "ipv6": ipv6
        }

    except Exception:

        return None


# =========================================================
# RECON COMPLETO
# =========================================================

def executar_scan(target):

    inicio = time.time()

    started_at = agora()

    # =====================================================
    # HEADER
    # =====================================================

    print()

    linha()

    print(
        f"              🔎 RECON TOOL {VERSION}"
    )

    linha()

    print()

    print(
        f"[+] Alvo: {target}"
    )

    print(
        "[+] Iniciando enumeração..."
    )

    print()

    # =====================================================
    # ENUMERAÇÃO
    # =====================================================

    try:

        subdominios = enumerar_subdominios(
            target
        )

    except Exception as erro:

        print(
            f"[-] Falha na enumeração: {erro}"
        )

        subdominios = []

    subdominios = sorted(
        set(
            normalizar_lista(
                subdominios
            )
        )
    )

    # Garante que o alvo esteja presente

    if target not in subdominios:

        subdominios.append(
            target
        )

    subdominios = sorted(
        set(
            subdominios
        )
    )

    print(
        f"[+] Total de hosts encontrados: "
        f"{len(subdominios)}"
    )

    # =====================================================
    # RESULTADO BASE
    # =====================================================

    resultado = {

        "target": target,

        "version": VERSION,

        "enumeration": {
            "source": "crt.sh",
            "subdomains": subdominios
        },

        "hosts": {},

        "scan": {
            "started_at": started_at
        },

        "summary": {

            "total_hosts": 0,

            "resolved_hosts": 0,

            "unresolved_hosts": 0,

            "total_open_ports": 0,

            "total_technologies": 0,

            "total_web_services": 0,

            "total_web_observations": 0,

            "total_cves_possible": 0,

            "cve_hosts": 0,

            "risk_hosts": 0
        }
    }

    # =====================================================
    # ANÁLISE DOS HOSTS
    # =====================================================

    for host in subdominios:

        print()

        print("-" * 58)

        print(
            f"[+] Analisando: {host}"
        )

        print("-" * 58)

        # -------------------------------------------------
        # DNS
        # -------------------------------------------------

        ip_info = resolver_host(
            host
        )

        if not ip_info:

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

        # -------------------------------------------------
        # PORT SCAN
        # -------------------------------------------------

        print(
            "[+] Executando port scan..."
        )

        try:

            portas = scan_ports(
                host
            )

        except TypeError:

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

            if porta.get(
                "status"
            ) == "open":

                portas_abertas.append(
                    porta
                )

        print(
            f"[+] Portas abertas: "
            f"{len(portas_abertas)}"
        )

        # -------------------------------------------------
        # HTTP / HTTPS
        # -------------------------------------------------

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

        # -------------------------------------------------
        # HOST FINAL
        # -------------------------------------------------

        resultado["hosts"][host] = preparar_host(

            hostname=host,

            ip_info=ip_info,

            status="resolved",

            portas=portas_abertas
        )

    # =====================================================
    # RESUMO
    # =====================================================

    finished_at = agora()

    duration = (
        time.time()
        - inicio
    )

    hosts = resultado[
        "hosts"
    ]

    resolved_hosts = sum(

        1

        for dados in hosts.values()

        if dados.get(
            "status"
        ) == "resolved"
    )

    unresolved_hosts = sum(

        1

        for dados in hosts.values()

        if dados.get(
            "status"
        ) == "unresolved"
    )

    total_open_ports = sum(

        len(

            [

                porta

                for porta in dados.get(
                    "ports",
                    []
                )

                if porta.get(
                    "status"
                ) == "open"

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

        "finished_at":
            finished_at,

        "duration_seconds":
            duration
    })

    resultado["summary"].update({

        "total_hosts":
            len(hosts),

        "resolved_hosts":
            resolved_hosts,

        "unresolved_hosts":
            unresolved_hosts,

        "total_open_ports":
            total_open_ports,

        "total_technologies":
            total_technologies
    })

    # =====================================================
    # RECON INTELLIGENCE
    # =====================================================

    print()

    print(
        "[+] Executando RECON INTELLIGENCE..."
    )

    try:

        analysis = analyze_result(
            resultado
        )

        resultado[
            "intelligence"
        ] = analysis

        exposure = (
            analysis.get(
                "exposure",
                {}
            )
        )

        resultado[
            "summary"
        ][
            "total_web_services"
        ] = exposure.get(
            "web_services",
            0
        )

        resultado[
            "summary"
        ][
            "total_web_observations"
        ] = exposure.get(
            "web_observations",
            0
        )

        print_intelligence(
            analysis
        )

    except Exception as erro:

        print(
            f"[-] Falha na RECON INTELLIGENCE: "
            f"{erro}"
        )

        resultado[
            "intelligence"
        ] = {
            "error": str(erro)
        }

    # =====================================================
    # RECON CVE CORRELATION 4.1
    # =====================================================

    print()

    print(
        "[+] Executando RECON CVE CORRELATION..."
    )

    try:

        cve_analysis = correlacionar_resultado(
            resultado
        )

        resultado[
            "cve_correlation"
        ] = cve_analysis

        # -------------------------------------------------
        # Estatísticas CVE
        # -------------------------------------------------

        resultado[
            "summary"
        ][
            "total_cves_possible"
        ] = cve_analysis.get(
            "cves_possiveis_total",
            0
        )

        resultado[
            "summary"
        ][
            "cve_hosts"
        ] = cve_analysis.get(
            "hosts_com_cves_possiveis",
            0
        )

        # -------------------------------------------------
        # Copia CVEs possíveis para cada host
        # -------------------------------------------------

        hosts_cve = cve_analysis.get(
            "hosts",
            {}
        )

        if isinstance(
            hosts_cve,
            dict
        ):

            for host, dados_cve in hosts_cve.items():

                if host not in resultado[
                    "hosts"
                ]:
                    continue

                if not isinstance(
                    dados_cve,
                    dict
                ):
                    continue

                possiveis = (
                    dados_cve.get(
                        "cves_possiveis",
                        []
                    )
                )

                resultado[
                    "hosts"
                ][
                    host
                ][
                    "cves"
                ] = possiveis

        print_cve_correlation(
            cve_analysis
        )

    except Exception as erro:

        print(
            f"[-] Falha na RECON CVE CORRELATION: "
            f"{erro}"
        )

        resultado[
            "cve_correlation"
        ] = {
            "error": str(erro)
        }

    # =====================================================
    # RECON RISK PRIORITIZATION 4.1.2
    # =====================================================

    print()

    print(
        "[+] Executando RECON RISK PRIORITIZATION..."
    )

    try:

        risk_analysis = analisar_risco(
            resultado
        )

        resultado[
            "risk_prioritization"
        ] = risk_analysis

        ranking = risk_analysis.get(
            "ranking",
            []
        )

        resultado[
            "summary"
        ][
            "risk_hosts"
        ] = len(
            ranking
        )

        print()

        print("=" * 58)

        print(
            "              🎯 RISK PRIORITIZATION 4.1.2"
        )

        print("=" * 58)

        print()

        print(
            "⚠️ Score heurístico de priorização."
        )

        print(
            "   Não constitui confirmação de vulnerabilidade."
        )

        print()

        if ranking:

            print(
                "📊 PRIORIDADE DE INVESTIGAÇÃO:"
            )

            for indice, item in enumerate(
                ranking,
                start=1
            ):

                print(

                    f"   {indice}. "
                    f"{item.get('host', '?')} "
                    f"→ "
                    f"{item.get('score', 0)}/100 "
                    f"[{item.get('nivel', '?')}]"

                )

        else:

            print(
                "   Nenhum host disponível."
            )

        print()

        print("=" * 58)

    except Exception as erro:

        print(
            "[-] Falha na "
            "RECON RISK PRIORITIZATION: "
            f"{erro}"
        )

        resultado[
            "risk_prioritization"
        ] = {
            "error": str(erro)
        }

    # =====================================================
    # RELATÓRIO DE RISCO
    # =====================================================

    print()

    print(
        "[+] Gerando relatório de risco..."
    )

    try:

        gerar_relatorio_markdown(
            resultado,
            RISK_REPORT_FILE
        )

        print(
            f"[+] Relatório de risco salvo em "
            f"{RISK_REPORT_FILE}"
        )

    except Exception as erro:

        print(
            "[-] Erro ao gerar relatório de risco: "
            f"{erro}"
        )

    # =====================================================
    # SALVAR JSON
    # =====================================================

    print()

    print(
        "[+] Salvando resultado completo..."
    )

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

        print(
            f"[+] Relatório completo salvo em "
            f"{REPORT_FILE}"
        )

    except Exception as erro:

        print()

        print(
            f"[-] Erro ao salvar "
            f"{REPORT_FILE}: {erro}"
        )

    # =====================================================
    # RESULTADO FINAL
    # =====================================================

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


# =========================================================
# MAIN
# =========================================================

def main():

    if len(sys.argv) > 1:

        target = sys.argv[
            1
        ].strip()

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


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()