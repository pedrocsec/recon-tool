"""
RECON TOOL 4.1.2
Risk Score / Priorização

Pontuação heurística de 0 a 100 para priorizar investigação.

IMPORTANTE:
O score NÃO confirma vulnerabilidade.
Ele representa somente prioridade de investigação com base
nos sinais observados pelo Recon Tool.
"""

from typing import Any, Dict, List


VERSION = "4.1.2"

WARNING = (
    "Pontuação heurística de priorização. "
    "Não constitui confirmação de vulnerabilidade."
)

MAX_SCORE = 100

CVSS_WEIGHT = 60
EXPOSURE_WEIGHT = 20
SECURITY_HEADER_WEIGHT = 10
HTTPS_WEIGHT = 10


# Portas que merecem atenção especial.
SENSITIVE_PORTS = {
    21: 4,
    22: 3,
    23: 5,
    25: 3,
    3306: 10,
    5432: 10,
    6379: 10,
    27017: 10,
    9200: 8,
    2375: 12,
    3389: 6,
    5900: 6,
}


# ============================================================
# UTILITÁRIOS
# ============================================================

def numero_seguro(valor, padrao=0.0):
    try:
        return float(valor)
    except (TypeError, ValueError):
        return padrao


def limitar(valor, minimo=0.0, maximo=100.0):
    return max(minimo, min(valor, maximo))


# ============================================================
# CVSS
# ============================================================

def extrair_cvss(item):
    if not isinstance(item, dict):
        return None

    campos = (
        "cvss",
        "cvss_score",
        "base_score",
        "score",
    )

    for campo in campos:
        valor = item.get(campo)

        if isinstance(valor, (int, float)):
            return float(valor)

        if isinstance(valor, str):
            try:
                return float(valor)
            except ValueError:
                pass

    estruturas = (
        item.get("cvss_v3"),
        item.get("cvss_v31"),
        item.get("cvss_v30"),
        item.get("cvss_v2"),
        item.get("metrics"),
    )

    for estrutura in estruturas:
        if isinstance(estrutura, dict):
            valor = extrair_cvss(estrutura)

            if valor is not None:
                return valor

    return None


def calcular_pontos_cvss(cves):
    if not isinstance(cves, list):
        return 0.0, None

    scores = []

    def coletar(obj):
        if isinstance(obj, dict):
            score = extrair_cvss(obj)

            if score is not None:
                scores.append(score)

            for valor in obj.values():
                if isinstance(valor, (dict, list)):
                    coletar(valor)

        elif isinstance(obj, list):
            for item in obj:
                coletar(item)

    coletar(cves)

    if not scores:
        return 0.0, None

    maior_cvss = max(
        limitar(score, 0, 10)
        for score in scores
    )

    pontos = (
        maior_cvss / 10.0
    ) * CVSS_WEIGHT

    return round(pontos, 2), maior_cvss


# ============================================================
# EXPOSIÇÃO / PORTAS
# ============================================================

def calcular_pontos_portas(ports):
    """
    Calcula até 20 pontos.

    A lógica diferencia:
    - portas sensíveis;
    - portas web alternativas;
    - exposição web padrão.

    Isso representa prioridade de investigação,
    não severidade de vulnerabilidade.
    """

    if not isinstance(ports, list):
        return 0.0, []

    pontos = 0.0
    detectadas = []

    for porta in ports:
        if not isinstance(porta, dict):
            continue

        if porta.get("status") != "open":
            continue

        numero = porta.get("port")

        try:
            numero = int(numero)
        except (TypeError, ValueError):
            continue

        if numero in detectadas:
            continue

        detectadas.append(numero)

        # Portas sensíveis recebem o peso definido acima.
        if numero in SENSITIVE_PORTS:
            pontos += SENSITIVE_PORTS[numero]

        # Portas web alternativas indicam superfície adicional.
        elif numero == 8080:
            pontos += 3

        elif numero == 8443:
            pontos += 3

        # HTTP/HTTPS padrão representam exposição normal.
        elif numero in (80, 443):
            pontos += 1

    pontos = limitar(
        pontos,
        0,
        EXPOSURE_WEIGHT
    )

    return round(pontos, 2), sorted(detectadas)


# ============================================================
# SECURITY HEADERS
# ============================================================

HEADERS_CONHECIDOS = {
    "hsts",
    "csp",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


def coletar_security_headers(obj, resultados=None):
    if resultados is None:
        resultados = []

    if isinstance(obj, dict):

        security = obj.get("security_headers")

        if isinstance(security, dict):
            resultados.append(security)

        for valor in obj.values():
            if isinstance(valor, (dict, list)):
                coletar_security_headers(
                    valor,
                    resultados
                )

    elif isinstance(obj, list):

        for item in obj:
            coletar_security_headers(
                item,
                resultados
            )

    return resultados


def normalizar_header(nome):
    return str(nome).strip().lower()


def calcular_pontos_headers(host_data):
    """
    Deduplica headers ausentes.

    Máximo: 10 pontos.
    """

    estruturas = coletar_security_headers(
        host_data
    )

    if not estruturas:
        return 0.0, []

    ausentes = set()

    for estrutura in estruturas:

        for nome, dados in estrutura.items():

            nome_normalizado = normalizar_header(nome)

            if nome_normalizado not in HEADERS_CONHECIDOS:
                continue

            presente = None

            if isinstance(dados, dict):
                presente = dados.get("presente")

            elif isinstance(dados, bool):
                presente = dados

            if presente is False:
                ausentes.add(nome_normalizado)

    quantidade = len(ausentes)

    if quantidade == 0:
        return 0.0, []

    pontos = (
        quantidade / len(HEADERS_CONHECIDOS)
    ) * SECURITY_HEADER_WEIGHT

    pontos = limitar(
        pontos,
        0,
        SECURITY_HEADER_WEIGHT
    )

    return round(pontos, 2), sorted(ausentes)


# ============================================================
# HTTPS
# ============================================================

def analisar_https(host_data):

    https_encontrado = False
    http_encontrado = False

    def visitar(obj):

        nonlocal https_encontrado
        nonlocal http_encontrado

        if isinstance(obj, dict):

            protocolo = str(
                obj.get("protocol", "")
            ).lower()

            if protocolo == "https":

                if (
                    obj.get("reachable") is True
                    or obj.get("status_code") is not None
                ):
                    https_encontrado = True

            if protocolo == "http":

                if (
                    obj.get("reachable") is True
                    or obj.get("status_code") is not None
                ):
                    http_encontrado = True

            if obj.get("https") is True:
                https_encontrado = True

            for valor in obj.values():

                if isinstance(valor, (dict, list)):
                    visitar(valor)

        elif isinstance(obj, list):

            for item in obj:
                visitar(item)

    visitar(host_data)

    return (
        https_encontrado,
        http_encontrado
    )


def calcular_pontos_https(host_data):

    https, http = analisar_https(
        host_data
    )

    if http and not https:
        return HTTPS_WEIGHT, True

    return 0.0, False


# ============================================================
# CLASSIFICAÇÃO
# ============================================================

def classificar_score(score):

    if score >= 75:
        return "CRÍTICA"

    if score >= 50:
        return "ALTA"

    if score >= 25:
        return "MODERADA"

    return "BAIXA"


# ============================================================
# SCORE PRINCIPAL
# ============================================================

def calcular_risco(host, dados):

    if not isinstance(dados, dict):
        dados = {}

    cves = dados.get("cves", [])
    ports = dados.get("ports", [])

    pontos_cvss, maior_cvss = (
        calcular_pontos_cvss(cves)
    )

    pontos_portas, portas_expostas = (
        calcular_pontos_portas(ports)
    )

    pontos_headers, headers_ausentes = (
        calcular_pontos_headers(dados)
    )

    pontos_https, https_ausente = (
        calcular_pontos_https(dados)
    )

    score = (
        pontos_cvss
        + pontos_portas
        + pontos_headers
        + pontos_https
    )

    score = round(
        limitar(score, 0, MAX_SCORE),
        2
    )

    return {
        "score": score,

        "nivel": classificar_score(score),

        "aviso": WARNING,

        "componentes": {

            "cvss": {
                "pontos": pontos_cvss,
                "maximo": CVSS_WEIGHT,
                "maior_cvss": maior_cvss,
            },

            "portas_sensiveis": {
                "pontos": pontos_portas,
                "maximo": EXPOSURE_WEIGHT,
                "portas": portas_expostas,
            },

            "security_headers": {
                "pontos": pontos_headers,
                "maximo": SECURITY_HEADER_WEIGHT,
                "ausentes": headers_ausentes,
            },

            "https": {
                "pontos": pontos_https,
                "maximo": HTTPS_WEIGHT,
                "https_ausente": https_ausente,
            },
        },
    }


# ============================================================
# APLICAR A TODOS OS HOSTS
# ============================================================

def analisar_risco(resultado):

    hosts = resultado.get(
        "hosts",
        {}
    )

    if not isinstance(hosts, dict):
        hosts = {}

    ranking = []

    for host, dados in hosts.items():

        risco = calcular_risco(
            host,
            dados
        )

        dados["risk_score"] = risco

        ranking.append({
            "host": host,
            "score": risco["score"],
            "nivel": risco["nivel"],
        })

    ranking.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    return {
        "version": VERSION,
        "aviso": WARNING,
        "ranking": ranking,
    }


# ============================================================
# RELATÓRIO MARKDOWN
# ============================================================

def gerar_relatorio_markdown(resultado, caminho):

    ranking_data = resultado.get(
        "risk_prioritization",
        {}
    )

    ranking = ranking_data.get(
        "ranking",
        []
    )

    linhas = []

    linhas.append(
        "# Recon Tool 4.1 — Priorização de Risco"
    )

    linhas.append("")

    linhas.append(
        "> ⚠️ O Risk Score é uma heurística de priorização. "
        "Ele NÃO confirma vulnerabilidade."
    )

    linhas.append("")

    linhas.append(
        f"**Alvo:** {resultado.get('target', '?')}"
    )

    linhas.append("")

    linhas.append(
        "## Ranking de investigação"
    )

    linhas.append("")

    if not ranking:

        linhas.append(
            "Nenhum host foi analisado."
        )

    else:

        for indice, item in enumerate(
            ranking,
            start=1
        ):

            host = item.get(
                "host",
                "?"
            )

            score = item.get(
                "score",
                0
            )

            nivel = item.get(
                "nivel",
                "?"
            )

            dados = (
                resultado
                .get("hosts", {})
                .get(host, {})
            )

            componentes = (
                dados
                .get("risk_score", {})
                .get("componentes", {})
            )

            linhas.append(
                f"### {indice}. {host}"
            )

            linhas.append("")

            linhas.append(
                f"**Score:** {score}/100 — "
                f"**{nivel}**"
            )

            linhas.append("")

            cvss = componentes.get(
                "cvss",
                {}
            )

            portas = componentes.get(
                "portas_sensiveis",
                {}
            )

            headers = componentes.get(
                "security_headers",
                {}
            )

            https = componentes.get(
                "https",
                {}
            )

            linhas.append(
                f"- CVSS: "
                f"{cvss.get('pontos', 0)}/60"
            )

            if cvss.get("maior_cvss") is not None:

                linhas.append(
                    f"  - Maior CVSS: "
                    f"{cvss.get('maior_cvss')}"
                )

            linhas.append(
                f"- Exposição de portas: "
                f"{portas.get('pontos', 0)}/20"
            )

            portas_detectadas = portas.get(
                "portas",
                []
            )

            if portas_detectadas:

                linhas.append(
                    "  - Portas observadas: "
                    + ", ".join(
                        str(p)
                        for p in portas_detectadas
                    )
                )

            linhas.append(
                f"- Security headers: "
                f"{headers.get('pontos', 0)}/10"
            )

            ausentes = headers.get(
                "ausentes",
                []
            )

            if ausentes:

                linhas.append(
                    "  - Ausentes: "
                    + ", ".join(ausentes)
                )

            linhas.append(
                f"- HTTPS ausente: "
                f"{'sim' if https.get('https_ausente') else 'não'}"
            )

            linhas.append("")

    linhas.append("---")

    linhas.append("")

    linhas.append(
        "O ranking representa somente prioridade de "
        "investigação com base nos sinais coletados."
    )

    with open(
        caminho,
        "w",
        encoding="utf-8"
    ) as arquivo:

        arquivo.write(
            "\n".join(linhas)
        )