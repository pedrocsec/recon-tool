"""
Recon Tool — Intelligence Module 4.1

Transforma dados brutos do recon em observações estruturadas.

Uso autorizado:
- laboratórios
- CTFs
- bug bounty dentro do escopo
- ativos próprios
"""

from typing import Dict, List, Any


def resposta_web_confirmada(dados: Any) -> bool:

    if not isinstance(dados, dict):
        return False

    if dados.get("reachable"):
        return True

    return dados.get("status_code") is not None


def analisar_security_headers(
    hostname: str,
    web_data: Dict[str, Any]
) -> List[Dict[str, str]]:

    observations = []
    vistas = set()

    for porta, dados_porta in web_data.items():

        if not isinstance(dados_porta, dict):
            continue

        for protocolo in ("http", "https"):

            dados = dados_porta.get(protocolo)

            if not resposta_web_confirmada(dados):
                continue

            headers = dados.get(
                "security_headers",
                {}
            )

            if not isinstance(headers, dict):
                continue

            ausentes = []

            for nome, info in headers.items():

                if not isinstance(info, dict):
                    continue

                presente = info.get(
                    "presente",
                    False
                )

                if not presente:
                    ausentes.append(nome)

            if not ausentes:
                continue

            chave = (
                str(porta),
                protocolo,
                tuple(ausentes)
            )

            if chave in vistas:
                continue

            vistas.add(chave)

            observations.append({
                "severity": "attention",
                "title": (
                    f"Security headers ausentes "
                    f"em {protocolo.upper()} "
                    f"na porta {porta}"
                ),
                "detail": (
                    ", ".join(ausentes)
                )
            })

    return observations


def analisar_web(
    hostname: str,
    web_data: Dict[str, Any]
) -> List[Dict[str, str]]:

    observations = []

    for porta, dados_porta in web_data.items():

        if not isinstance(
            dados_porta,
            dict
        ):
            continue

        for protocolo in (
            "http",
            "https"
        ):

            dados = dados_porta.get(
                protocolo
            )

            if not isinstance(
                dados,
                dict
            ):
                continue

            if not dados.get(
                "reachable"
            ):
                continue

            status = dados.get(
                "status_code"
            )

            titulo = dados.get(
                "title"
            )

            if status is not None:

                detalhe = (
                    f"{protocolo.upper()} "
                    f"respondeu com HTTP "
                    f"{status}."
                )

                if titulo:
                    detalhe += (
                        f" Título: {titulo}."
                    )

                observations.append({
                    "severity": "info",
                    "title": (
                        f"Serviço web confirmado "
                        f"na porta {porta}"
                    ),
                    "detail": detalhe
                })

            redirects = dados.get(
                "redirect_count",
                0
            )

            if redirects:

                observations.append({
                    "severity": "info",
                    "title": (
                        f"Redirects detectados "
                        f"na porta {porta}"
                    ),
                    "detail": (
                        f"{redirects} redirect(s) "
                        f"observado(s) em "
                        f"{protocolo.upper()}."
                    )
                })

    return observations


def analisar_tecnologias(
    technologies: List[Dict[str, Any]]
) -> List[Dict[str, str]]:

    observations = []

    for technology in technologies:

        if not isinstance(
            technology,
            dict
        ):
            continue

        name = technology.get(
            "name",
            "Tecnologia desconhecida"
        )

        version = technology.get(
            "version"
        )

        source = technology.get(
            "source",
            "desconhecida"
        )

        if version:

            detail = (
                f"Fingerprint obtido "
                f"através de {source}. "
                f"Versão detectada: {version}."
            )

        else:

            detail = (
                f"Fingerprint obtido "
                f"através de {source}."
            )

        observations.append({
            "severity": "info",
            "title": (
                f"Tecnologia: {name}"
            ),
            "detail": detail
        })

    return observations


def contar_observacoes_web(
    web_data: Dict[str, Any]
) -> int:

    total = 0

    if not isinstance(web_data, dict):
        return 0

    for dados_porta in web_data.values():

        if not isinstance(dados_porta, dict):
            continue

        for protocolo in ("http", "https"):

            if resposta_web_confirmada(
                dados_porta.get(protocolo)
            ):
                total += 1

    return total


def contar_servicos_web(
    web_data: Dict[str, Any]
) -> int:

    total = 0

    if not isinstance(web_data, dict):
        return 0

    for dados_porta in web_data.values():

        if not isinstance(dados_porta, dict):
            continue

        confirmado = False

        for protocolo in ("http", "https"):

            if resposta_web_confirmada(
                dados_porta.get(protocolo)
            ):
                confirmado = True
                break

        if confirmado:
            total += 1

    return total


def analyze_host(
    hostname: str,
    data: Dict[str, Any]
) -> Dict[str, Any]:

    observations = []

    status = data.get(
        "status",
        "unknown"
    )

    ports = data.get(
        "ports",
        []
    )

    technologies = data.get(
        "technologies",
        []
    )

    web = data.get(
        "web",
        {}
    )

    # ======================================================
    # DNS
    # ======================================================

    if status == "resolved":

        observations.append({
            "severity": "info",
            "title": "Host resolvido",
            "detail": (
                "O hostname possui "
                "resolução DNS."
            )
        })

    elif status == "unresolved":

        observations.append({
            "severity": "info",
            "title": "DNS não resolvido",
            "detail": (
                "Nenhum endereço IP foi "
                "obtido durante a análise."
            )
        })

        return {
            "hostname": hostname,
            "status": status,
            "open_ports": 0,
            "technologies": 0,
            "web_services": 0,
            "web_observations": 0,
            "observations": observations
        }

    # ======================================================
    # PORTAS
    # ======================================================

    open_ports = [
        port
        for port in ports
        if port.get("status") == "open"
    ]

    if open_ports:

        observations.append({
            "severity": "attention",
            "title": "Portas abertas",
            "detail": (
                f"{len(open_ports)} porta(s) "
                "foram identificadas como abertas."
            )
        })

    alternate_ports = {
        8080: "HTTP alternativo",
        8000: "HTTP alternativo",
        8081: "HTTP alternativo",
        8443: "HTTPS alternativo",
        8888: "HTTP alternativo"
    }

    for port in open_ports:

        port_number = port.get(
            "port"
        )

        if port_number in alternate_ports:

            observations.append({
                "severity": "attention",
                "title": (
                    f"Porta alternativa "
                    f"{port_number}"
                ),
                "detail": (
                    f"{alternate_ports[port_number]} "
                    "detectado. O serviço deve "
                    "ser validado."
                )
            })

    # ======================================================
    # WEB
    # ======================================================

    observations.extend(
        analisar_web(
            hostname,
            web
        )
    )

    observations.extend(
        analisar_security_headers(
            hostname,
            web
        )
    )

    # ======================================================
    # TECNOLOGIAS
    # ======================================================

    observations.extend(
        analisar_tecnologias(
            technologies
        )
    )

    # ======================================================
    # SERVIÇOS WEB
    # ======================================================

    web_services = contar_servicos_web(
        web
    )

    web_observations = contar_observacoes_web(
        web
    )

    return {
        "hostname": hostname,
        "status": status,
        "open_ports": len(open_ports),
        "technologies": len(technologies),
        "web_services": web_services,
        "web_observations": web_observations,
        "observations": observations
    }


def analyze_result(
    result: Dict[str, Any]
) -> Dict[str, Any]:

    hosts = result.get(
        "hosts",
        {}
    )

    analyzed_hosts = {}

    total_open_ports = 0
    total_technologies = 0
    total_web_services = 0
    total_web_observations = 0

    for hostname, host_data in hosts.items():

        analysis = analyze_host(
            hostname,
            host_data
        )

        analyzed_hosts[
            hostname
        ] = analysis

        total_open_ports += (
            analysis["open_ports"]
        )

        total_technologies += (
            analysis["technologies"]
        )

        total_web_services += (
            analysis["web_services"]
        )

        total_web_observations += (
            analysis.get(
                "web_observations",
                0
            )
        )

    resolved_hosts = sum(
        1
        for host in hosts.values()
        if host.get("status")
        == "resolved"
    )

    unresolved_hosts = sum(
        1
        for host in hosts.values()
        if host.get("status")
        == "unresolved"
    )

    if total_open_ports == 0:

        exposure = "BAIXA"

    elif total_open_ports <= 4:

        exposure = "MODERADA"

    else:

        exposure = "ELEVADA"

    return {
        "exposure": {
            "level": exposure,
            "resolved_hosts": resolved_hosts,
            "unresolved_hosts": unresolved_hosts,
            "open_ports": total_open_ports,
            "technologies": total_technologies,
            "web_services": total_web_services,
            "web_observations": total_web_observations
        },
        "hosts": analyzed_hosts
    }


def print_intelligence(
    analysis: Dict[str, Any]
) -> None:

    exposure = analysis.get(
        "exposure",
        {}
    )

    print()

    print("=" * 58)

    print(
        "              🧠 RECON INTELLIGENCE 4.1.2"
    )

    print("=" * 58)

    print()

    print("📊 EXPOSIÇÃO")

    print()

    print(
        f"   Hosts resolvidos:      "
        f"{exposure.get('resolved_hosts', 0)}"
    )

    print(
        f"   Hosts não resolvidos:  "
        f"{exposure.get('unresolved_hosts', 0)}"
    )

    print(
        f"   Portas abertas:        "
        f"{exposure.get('open_ports', 0)}"
    )

    print(
        f"   Serviços web:          "
        f"{exposure.get('web_services', 0)}"
    )

    print(
        f"   Observações HTTP/HTTPS:"
        f" {exposure.get('web_observations', 0)}"
    )

    print(
        f"   Tecnologias:           "
        f"{exposure.get('technologies', 0)}"
    )

    print()

    print(
        f"   NÍVEL DE EXPOSIÇÃO: "
        f"{exposure.get('level', 'DESCONHECIDO')}"
    )

    print()

    print("-" * 58)

    for hostname, host in analysis.get(
        "hosts",
        {}
    ).items():

        print()

        print(
            f"🎯 {hostname}"
        )

        observations = host.get(
            "observations",
            []
        )

        if not observations:

            print(
                "   Nenhuma observação adicional."
            )

            continue

        for observation in observations:

            severity = observation.get(
                "severity"
            )

            title = observation.get(
                "title"
            )

            detail = observation.get(
                "detail"
            )

            if severity == "attention":

                icon = "⚠️"

            elif severity == "info":

                icon = "ℹ️"

            else:

                icon = "•"

            print(
                f"   {icon} {title}"
            )

            print(
                f"      └─ {detail}"
            )

    print()

    print("=" * 58)