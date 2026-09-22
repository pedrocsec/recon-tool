"""
Recon Tool — Security Headers 3.7

Helper opcional. A análise principal de headers no pipeline
vem de techdetect + intelligence sobre o schema aninhado.
"""

from typing import Dict, Any, List


SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "Força o uso de HTTPS.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "description": "Ajuda a restringir fontes e conteúdos executáveis.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Ajuda a impedir MIME sniffing.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controla informações enviadas no Referer.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controla recursos e APIs disponíveis ao navegador.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Ajuda a controlar carregamento em frames.",
    },
}


def analyze_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(headers, dict):
        headers = {}

    normalized = {
        str(key).lower(): value
        for key, value in headers.items()
    }

    results: List[Dict[str, Any]] = []

    for header, metadata in SECURITY_HEADERS.items():
        if header in normalized:
            results.append({
                "header": metadata["name"],
                "status": "present",
                "value": normalized[header],
                "description": metadata["description"],
            })
        else:
            results.append({
                "header": metadata["name"],
                "status": "not_observed",
                "value": None,
                "description": metadata["description"],
            })

    return {
        "headers_checked": len(SECURITY_HEADERS),
        "headers_present": sum(
            1 for item in results if item["status"] == "present"
        ),
        "headers_not_observed": sum(
            1 for item in results if item["status"] == "not_observed"
        ),
        "results": results,
    }


def _iter_respostas_http(http_data):
    if not isinstance(http_data, dict):
        return

    nested = False

    for protocolo in ("http", "https"):
        dados = http_data.get(protocolo)
        if isinstance(dados, dict):
            nested = True
            yield protocolo, dados

    if not nested and http_data:
        yield http_data.get("protocol") or "unknown", http_data


def analyze_host_security(host_data: Dict[str, Any]) -> Dict[str, Any]:
    ports = host_data.get("ports", []) or []
    analyses = []

    for port_data in ports:
        if not isinstance(port_data, dict):
            continue

        if port_data.get("status") != "open":
            continue

        http_data = port_data.get("http")

        for protocol, resp in _iter_respostas_http(http_data):
            if not isinstance(resp, dict):
                continue

            # Somente respostas válidas
            if not resp.get("reachable") and resp.get("status_code") is None:
                continue

            headers = resp.get("headers") or {}

            if not headers:
                continue

            analyses.append({
                "port": port_data.get("port"),
                "protocol": protocol or resp.get("protocol"),
                "analysis": analyze_headers(headers),
            })

    return {
        "responses_analyzed": len(analyses),
        "responses": analyses,
    }


def print_security_headers(hostname: str, analysis: Dict[str, Any]) -> None:
    responses = analysis.get("responses", []) or []

    if not responses:
        return

    print()
    print(f"🛡️ SECURITY HEADERS — {hostname}")

    for response in responses:
        port = response.get("port")
        protocol = response.get("protocol") or "desconhecido"

        print()
        print(f"   🌐 Porta {port} — {str(protocol).upper()}")

        header_analysis = response.get("analysis", {}) or {}

        for item in header_analysis.get("results", []):
            name = item.get("header")
            status = item.get("status")
            value = item.get("value")

            if status == "present":
                print(f"      🟢 {name}: presente")
                if value:
                    print(f"         └─ Valor: {value}")
            else:
                print(f"      ⚪ {name}: não observado")

    print()
    print(
        "   ℹ️ Ausência de um header não significa "
        "automaticamente uma vulnerabilidade."
    )
