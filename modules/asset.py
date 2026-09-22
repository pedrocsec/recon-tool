"""
Recon Tool — Asset profile helper 3.7
"""


def _respostas_http(http):
    if not isinstance(http, dict):
        return []

    respostas = []

    if isinstance(http.get("http"), dict) or isinstance(http.get("https"), dict):
        for protocolo in ("http", "https"):
            dados = http.get(protocolo)
            if isinstance(dados, dict):
                respostas.append(dados)
        return respostas

    return [http]


def criar_perfil_host(host, dados):
    """Cria um perfil resumido e organizado de um host."""
    status = dados.get("status", "unknown")
    ip = dados.get("ip") or {}
    portas = dados.get("ports", []) or []
    tecnologias = dados.get("technologies", []) or []

    ipv4 = ip.get("ipv4", []) if isinstance(ip, dict) else []
    ipv6 = ip.get("ipv6", []) if isinstance(ip, dict) else []

    perfil = {
        "hostname": host,
        "status": status,
        "dns": {
            "resolved": status == "resolved",
            "ipv4": ipv4,
            "ipv6": ipv6,
        },
        "exposure": {
            "open_ports": len(portas),
            "ports": [],
        },
        "technologies": tecnologias,
        "role": "unknown",
    }

    for porta in portas:
        if not isinstance(porta, dict):
            continue

        porta_info = {
            "port": porta.get("port"),
            "status": porta.get("status"),
            "service_guess": porta.get("service_guess"),
            "http": None,
        }

        http = porta.get("http")
        respostas = []

        for resp in _respostas_http(http):
            if not isinstance(resp, dict):
                continue

            if not resp.get("reachable") and resp.get("status_code") is None:
                continue

            headers = resp.get("headers") or {}

            respostas.append({
                "service": resp.get("service"),
                "protocol": resp.get("protocol"),
                "status_code": resp.get("status_code"),
                "status": resp.get("status"),
                "final_url": resp.get("final_url"),
                "redirect_count": resp.get("redirect_count", 0),
                "title": resp.get("title"),
                "content_type": (
                    resp.get("content_type")
                    or headers.get("content-type")
                    or headers.get("Content-Type")
                ),
            })

        if respostas:
            porta_info["http"] = respostas

        perfil["exposure"]["ports"].append(porta_info)

    perfil["role"] = identificar_role(perfil)
    return perfil


def identificar_role(perfil):
    """Identifica o papel do host com evidências observadas."""
    if perfil["status"] != "resolved":
        return "unknown"

    for porta in perfil["exposure"]["ports"]:
        http = porta.get("http")

        if not http:
            continue

        # lista de respostas (schema 3.7) ou dict legado
        if isinstance(http, list):
            if http:
                return "web"
        elif isinstance(http, dict):
            if http.get("protocol") in ("http", "https"):
                return "web"

    return "unknown"
