"""
Recon Tool — DNS Module

Responsabilidade única: resolução DNS de hostnames.
Usado pelo main.py. Não realiza port scan nem HTTP.
"""

import socket


def consultar_dns(host):
    """
    Consulta informações DNS básicas de um host.

    Retorna:
    {
        "ipv4": [...],
        "ipv6": [...],
        "cname": str | None
    }

    Listas vazias significam que o tipo não foi encontrado.
    Em falha total de resolução, retorna listas vazias
    (o caller decide se o host é unresolved).
    """
    resultado = {
        "ipv4": [],
        "ipv6": [],
        "cname": None,
    }

    if host is None:
        return resultado

    host = str(host).strip().lower()

    if not host:
        return resultado

    # IPv4 e IPv6
    try:
        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for info in infos:
            familia = info[0]
            endereco = info[4][0]

            if familia == socket.AF_INET:
                if endereco not in resultado["ipv4"]:
                    resultado["ipv4"].append(endereco)
            elif familia == socket.AF_INET6:
                if endereco not in resultado["ipv6"]:
                    resultado["ipv6"].append(endereco)
            else:
                if ":" in endereco:
                    if endereco not in resultado["ipv6"]:
                        resultado["ipv6"].append(endereco)
                else:
                    if endereco not in resultado["ipv4"]:
                        resultado["ipv4"].append(endereco)

    except socket.gaierror:
        pass
    except Exception as erro:
        print(f"[-] Erro DNS em {host}: {erro}")

    # CNAME aproximado via FQDN (best-effort)
    try:
        cname = socket.getfqdn(host)

        if cname and cname.lower() != host.lower():
            resultado["cname"] = cname
    except Exception:
        pass

    return resultado


def resolver_host(host):
    """
    Resolve IPv4/IPv6 de um hostname.

    Retorna dict com ipv4/ipv6 se houver ao menos um endereço,
    ou None se o host não resolver (unresolved).
    """
    dados = consultar_dns(host)

    ipv4 = dados.get("ipv4") or []
    ipv6 = dados.get("ipv6") or []

    if not ipv4 and not ipv6:
        return None

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "cname": dados.get("cname"),
    }
