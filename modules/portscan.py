"""
Recon Tool — Port Scan Module 3.8

Responsabilidade:
- Verificar portas TCP.
- Identificar serviços conhecidos por porta.

Não realiza:
- DNS
- HTTP/HTTPS
- Technology Detection
"""

import socket
import time


VERSION = "3.8"

TIMEOUT = 1

PORTAS_PADRAO = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
]


SERVICOS_CONHECIDOS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def verificar_porta(host, porta):
    """
    Verifica se uma porta TCP está acessível.

    Retorna:

    {
        "open": bool,
        "latency_ms": float
    }
    """

    inicio = time.perf_counter()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(TIMEOUT)

    try:
        resultado = sock.connect_ex((host, porta))

        aberta = resultado == 0

        duracao = (
            time.perf_counter() - inicio
        ) * 1000

        return {
            "open": aberta,
            "latency_ms": round(duracao, 2),
        }

    except (
        socket.gaierror,
        socket.timeout,
        OSError,
    ):
        duracao = (
            time.perf_counter() - inicio
        ) * 1000

        return {
            "open": False,
            "latency_ms": round(duracao, 2),
        }

    finally:
        sock.close()


def scan_ports(host, portas=None):
    """
    Executa o port scan TCP.

    Retorna somente portas abertas.

    O campo "http" permanece None para o
    techdetect preencher posteriormente.
    """

    if portas is None:
        portas = PORTAS_PADRAO

    portas_abertas = []

    for porta in portas:

        resultado = verificar_porta(
            host,
            porta,
        )

        if not resultado["open"]:
            continue

        portas_abertas.append({
            "port": porta,
            "status": "open",
            "service_guess": SERVICOS_CONHECIDOS.get(
                porta,
                "TCP",
            ),
            "latency_ms": resultado["latency_ms"],
            "http": None,
        })

    return portas_abertas


def escanear_portas(host, portas=None):
    """
    Alias de compatibilidade.
    """

    return scan_ports(
        host,
        portas,
    )