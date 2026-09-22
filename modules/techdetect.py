"""
Recon Tool — HTTP / Technology Detection 3.9

Responsabilidade:
- Análise HTTP/HTTPS
- Detecção de tecnologias
- Extração de versões quando houver evidência direta

Schema oficial de analisar_http(host, porta):

{
    "http":  { ... resposta ... } | None,
    "https": { ... resposta ... } | None
}

Versões:
- Server header
- X-Powered-By
- HTML meta generator

Quando não houver evidência confiável:
    "version": None
"""

import re

import requests
import urllib3


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


VERSION = "3.9"

TIMEOUT = 8

USER_AGENT = (
    f"ReconTool/{VERSION} "
    "(authorized-security-testing)"
)


SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


STATUS_HTTP = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


def obter_status_http(status_code):
    return STATUS_HTTP.get(
        status_code,
        "Unknown"
    )


# =========================================================
# HTML
# =========================================================

def extrair_title(html):
    """
    Extrai o conteúdo da tag <title>.
    """

    if not html:
        return None

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return None

    titulo = re.sub(
        r"\s+",
        " ",
        match.group(1)
    )

    titulo = titulo.strip()

    if not titulo:
        return None

    return titulo[:200]


def extrair_meta_generator(html):
    """
    Procura:

        <meta name="generator" content="WordPress 6.6.1">

    ou:

        <meta content="WordPress 6.6.1" name="generator">

    Retorna somente o valor de content.
    """

    if not html:
        return None

    padroes = [

        # name antes de content
        re.compile(
            r'<meta\b'
            r'[^>]*\bname\s*=\s*["\']generator["\']'
            r'[^>]*\bcontent\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        ),

        # content antes de name
        re.compile(
            r'<meta\b'
            r'[^>]*\bcontent\s*=\s*["\']([^"\']+)["\']'
            r'[^>]*\bname\s*=\s*["\']generator["\']',
            re.IGNORECASE,
        ),
    ]

    for padrao in padroes:

        match = padrao.search(
            html
        )

        if match:

            valor = match.group(
                1
            ).strip()

            if valor:
                return valor

    return None


# =========================================================
# VERSION EXTRACTION
# =========================================================

def extrair_versao(texto, tecnologia):
    """
    Extrai uma versão somente quando existe
    uma associação direta entre tecnologia e número.

    Exemplos aceitos:

        Apache/2.4.29
        Apache 2.4.29
        nginx/1.24.0
        PHP/7.4
        PHP 8.2.12
        Microsoft-IIS/10.0

    Não inventa versão.

    Retorna:
        str | None
    """

    if not texto:
        return None

    padrao = re.compile(
        rf"\b{re.escape(tecnologia)}"
        rf"(?:[/\s-]+)"
        rf"(\d+(?:\.\d+){{1,3}})"
        rf"\b",
        re.IGNORECASE,
    )

    match = padrao.search(
        str(texto)
    )

    if not match:
        return None

    return match.group(
        1
    )


def extrair_versao_generator(
    generator,
    tecnologia
):
    """
    Extrai versão de um meta generator.

    Exemplos:

        WordPress 6.6.1
        Drupal 10.2.7
        Joomla 5.1.0
    """

    if not generator:
        return None

    padrao = re.compile(
        rf"\b{re.escape(tecnologia)}"
        rf"(?:[/\s-]+)"
        rf"(\d+(?:\.\d+){{1,3}})"
        rf"\b",
        re.IGNORECASE,
    )

    match = padrao.search(
        str(generator)
    )

    if not match:
        return None

    return match.group(
        1
    )


# =========================================================
# TECHNOLOGY MANAGEMENT
# =========================================================

def adicionar_tecnologia(
    tecnologias,
    nome,
    versao,
    source,
    evidence
):
    """
    Adiciona tecnologia sem duplicar.

    Se a tecnologia já existir sem versão
    e uma versão confiável aparecer depois,
    atualiza a entrada existente.
    """

    for tecnologia in tecnologias:

        if (
            tecnologia.get(
                "name",
                ""
            ).lower()
            == nome.lower()
        ):

            if (
                tecnologia.get(
                    "version"
                ) is None
                and versao is not None
            ):

                tecnologia[
                    "version"
                ] = versao

                tecnologia[
                    "source"
                ] = source

                tecnologia[
                    "evidence"
                ] = evidence

            return

    tecnologias.append({

        "name": nome,

        "version": versao,

        "source": source,

        "evidence": evidence,
    })


# =========================================================
# TECHNOLOGY DETECTION
# =========================================================

def identificar_tecnologias(
    headers,
    html,
    title
):
    """
    Detecta tecnologias através de evidências observáveis.

    Fontes:

    - HTTP Server
    - X-Powered-By
    - HTML
    - meta generator
    """

    tecnologias = []

    if not isinstance(
        headers,
        dict
    ):
        headers = {}

    headers_normalizados = {

        str(chave).lower():
            str(valor)

        for chave, valor
        in headers.items()
    }

    server = (
        headers_normalizados.get(
            "server",
            ""
        )
    )

    powered_by = (
        headers_normalizados.get(
            "x-powered-by",
            ""
        )
    )

    html_lower = (
        html.lower()
        if html
        else ""
    )

    title_lower = (
        title.lower()
        if title
        else ""
    )

    # =====================================================
    # CLOUDFLARE
    # =====================================================

    if (
        "cloudflare" in server.lower()
        or "cf-ray"
        in headers_normalizados
        or "cf-cache-status"
        in headers_normalizados
    ):

        adicionar_tecnologia(

            tecnologias,

            "Cloudflare",

            extrair_versao(
                server,
                "cloudflare"
            ),

            "http_headers",

            (
                f"Server: {server}"
                if server
                else
                "Header CF-* detectado"
            ),
        )

    # =====================================================
    # NGINX
    # =====================================================

    if "nginx" in server.lower():

        adicionar_tecnologia(

            tecnologias,

            "Nginx",

            extrair_versao(
                server,
                "nginx"
            ),

            "server_header",

            f"Server: {server}",
        )

    # =====================================================
    # APACHE
    # =====================================================

    if "apache" in server.lower():

        adicionar_tecnologia(

            tecnologias,

            "Apache",

            extrair_versao(
                server,
                "apache"
            ),

            "server_header",

            f"Server: {server}",
        )

    # =====================================================
    # MICROSOFT IIS
    # =====================================================

    if (
        "microsoft-iis"
        in server.lower()
    ):

        adicionar_tecnologia(

            tecnologias,

            "Microsoft IIS",

            extrair_versao(
                server,
                "microsoft-iis"
            ),

            "server_header",

            f"Server: {server}",
        )

    # =====================================================
    # PHP
    # =====================================================

    if "php" in powered_by.lower():

        adicionar_tecnologia(

            tecnologias,

            "PHP",

            extrair_versao(
                powered_by,
                "php"
            ),

            "x_powered_by",

            f"X-Powered-By: {powered_by}",
        )

    # =====================================================
    # ASP.NET
    # =====================================================

    if "asp.net" in powered_by.lower():

        adicionar_tecnologia(

            tecnologias,

            "ASP.NET",

            extrair_versao(
                powered_by,
                "asp.net"
            ),

            "x_powered_by",

            f"X-Powered-By: {powered_by}",
        )

    # =====================================================
    # WORDPRESS
    # =====================================================

    if (
        "wp-content" in html_lower
        or "wp-includes" in html_lower
        or "wordpress" in html_lower
    ):

        adicionar_tecnologia(

            tecnologias,

            "WordPress",

            None,

            "html_signature",

            "Padrão WordPress encontrado no HTML",
        )

    # =====================================================
    # NEXT.JS
    # =====================================================

    if (
        "__next" in html_lower
        or "__next_data__" in html_lower
    ):

        adicionar_tecnologia(

            tecnologias,

            "Next.js",

            None,

            "html_signature",

            "Estrutura __NEXT encontrada no HTML",
        )

    # =====================================================
    # REACT
    # =====================================================

    if (
        "react" in html_lower
        or "react" in title_lower
    ):

        adicionar_tecnologia(

            tecnologias,

            "React",

            None,

            "html_signature",

            "Referência React encontrada no HTML",
        )

    # =====================================================
    # VUE.JS
    # =====================================================

    if (
        "vue" in html_lower
        or "vue" in title_lower
    ):

        adicionar_tecnologia(

            tecnologias,

            "Vue.js",

            None,

            "html_signature",

            "Referência Vue encontrada no HTML",
        )

    # =====================================================
    # JQUERY
    # =====================================================

    if "jquery" in html_lower:

        adicionar_tecnologia(

            tecnologias,

            "jQuery",

            extrair_versao(
                html_lower,
                "jquery"
            ),

            "html_signature",

            "Referência jQuery encontrada no HTML",
        )

    # =====================================================
    # BOOTSTRAP
    # =====================================================

    if (
        "bootstrap.min.css"
        in html_lower

        or

        "bootstrap.min.js"
        in html_lower
    ):

        adicionar_tecnologia(

            tecnologias,

            "Bootstrap",

            extrair_versao(
                html_lower,
                "bootstrap"
            ),

            "html_signature",

            "Referência Bootstrap encontrada no HTML",
        )

    # =====================================================
    # META GENERATOR
    # =====================================================

    generator = (
        extrair_meta_generator(
            html
        )
    )

    if generator:

        generator_lower = (
            generator.lower()
        )

        # -------------------------------------------------
        # WordPress
        # -------------------------------------------------

        if "wordpress" in generator_lower:

            adicionar_tecnologia(

                tecnologias,

                "WordPress",

                extrair_versao_generator(
                    generator,
                    "wordpress"
                ),

                "meta_generator",

                f"Meta generator: {generator}",
            )

        # -------------------------------------------------
        # Drupal
        # -------------------------------------------------

        if "drupal" in generator_lower:

            adicionar_tecnologia(

                tecnologias,

                "Drupal",

                extrair_versao_generator(
                    generator,
                    "drupal"
                ),

                "meta_generator",

                f"Meta generator: {generator}",
            )

        # -------------------------------------------------
        # Joomla
        # -------------------------------------------------

        if "joomla" in generator_lower:

            adicionar_tecnologia(

                tecnologias,

                "Joomla",

                extrair_versao_generator(
                    generator,
                    "joomla"
                ),

                "meta_generator",

                f"Meta generator: {generator}",
            )

    return tecnologias


# =========================================================
# SECURITY HEADERS
# =========================================================

def analisar_security_headers(
    headers
):
    """
    Analisa headers de segurança
    somente quando existe resposta real.
    """

    resultado = {}

    for header, nome in SECURITY_HEADERS.items():

        valor = None

        if isinstance(
            headers,
            dict
        ):

            valor = headers.get(
                header
            )

            if valor is None:

                for chave, v in headers.items():

                    if (
                        str(chave).lower()
                        == header.lower()
                    ):

                        valor = v

                        break

        resultado[nome] = {

            "presente":
                valor is not None,

            "valor":
                valor,
        }

    return resultado


# =========================================================
# UNREACHABLE RESPONSE
# =========================================================

def resposta_inalcancavel(
    protocolo,
    erro
):
    """
    Resposta de falha de conexão.

    security_headers vazio:
    não gera falso positivo de headers ausentes.
    """

    return {

        "reachable": False,

        "protocol": protocolo,

        "service": None,

        "status_code": None,

        "status": None,

        "title": None,

        "content_type": None,

        "server": None,

        "x_powered_by": None,

        "final_url": None,

        "redirect_count": 0,

        "redirects": [],

        "https": protocolo == "https",

        "content_length": 0,

        "headers": {},

        "security_headers": {},

        "cookies": [],

        "technologies": [],

        "error": str(erro),
    }


# =========================================================
# URL ANALYSIS
# =========================================================

def analisar_url(
    host,
    porta,
    protocolo
):
    """
    Analisa uma URL HTTP/HTTPS específica.
    """

    url = (
        f"{protocolo}://"
        f"{host}:"
        f"{porta}/"
    )

    try:

        resposta = requests.get(

            url,

            timeout=TIMEOUT,

            allow_redirects=True,

            verify=False,

            headers={
                "User-Agent":
                    USER_AGENT
            },
        )

        html = (
            resposta.text[:100000]
        )

        titulo = extrair_title(
            html
        )

        headers = dict(
            resposta.headers
        )

        tecnologias = (
            identificar_tecnologias(
                headers,
                html,
                titulo
            )
        )

        security_headers = (
            analisar_security_headers(
                headers
            )
        )

        # -------------------------------------------------
        # REDIRECTS
        # -------------------------------------------------

        redirects = []

        for redirect in (
            resposta.history
        ):

            redirects.append({

                "status_code":
                    redirect.status_code,

                "status":
                    obter_status_http(
                        redirect.status_code
                    ),

                "url":
                    redirect.url,

                "location":
                    redirect.headers.get(
                        "Location"
                    ),
            })

        # -------------------------------------------------
        # COOKIES
        # -------------------------------------------------

        cookies = []

        for cookie in (
            resposta.cookies
        ):

            cookies.append({

                "name":
                    cookie.name,

                "secure":
                    bool(
                        cookie.secure
                    ),

                "httponly":
                    "HttpOnly"
                    in cookie._rest,

                "samesite":
                    cookie._rest.get(
                        "SameSite"
                    ),
            })

        # -------------------------------------------------
        # CONTENT TYPE
        # -------------------------------------------------

        content_type = (
            resposta.headers.get(
                "Content-Type"
            )
        )

        service = None

        if content_type:

            content_type_lower = (
                content_type.lower()
            )

            if (
                "text/html"
                in content_type_lower
            ):

                service = "web"

            elif (
                "application/json"
                in content_type_lower
            ):

                service = "api/json"

            elif (
                "xml"
                in content_type_lower
            ):

                service = "xml"

            else:

                service = "http"

        # -------------------------------------------------
        # RESULTADO
        # -------------------------------------------------

        return {

            "reachable": True,

            "protocol": protocolo,

            "service":
                service or "http",

            "status_code":
                resposta.status_code,

            "status":
                obter_status_http(
                    resposta.status_code
                ),

            "title":
                titulo,

            "content_type":
                content_type,

            "server":
                resposta.headers.get(
                    "Server"
                ),

            "x_powered_by":
                resposta.headers.get(
                    "X-Powered-By"
                ),

            "final_url":
                resposta.url,

            "redirect_count":
                len(
                    resposta.history
                ),

            "redirects":
                redirects,

            "https":
                resposta.url.startswith(
                    "https://"
                ),

            "content_length":
                len(
                    resposta.content
                ),

            "headers":
                headers,

            "security_headers":
                security_headers,

            "cookies":
                cookies,

            "technologies":
                tecnologias,
        }

    except requests.exceptions.RequestException as erro:

        return resposta_inalcancavel(
            protocolo,
            erro
        )


# =========================================================
# PROTOCOLS
# =========================================================

def protocolos_para_porta(
    porta
):
    """
    Define quais protocolos tentar.

    Portas HTTP:
        HTTP primeiro.

    Portas TLS:
        HTTPS primeiro.

    Outras:
        HTTP + HTTPS.
    """

    try:

        porta = int(
            porta
        )

    except (
        TypeError,
        ValueError
    ):

        return (
            "http",
            "https"
        )

    if porta in (
        80,
        8080,
        8000,
        8081,
        8888,
        3000,
        5000
    ):

        return (
            "http",
            "https"
        )

    if porta in (
        443,
        8443,
        9443
    ):

        return (
            "https",
            "http"
        )

    return (
        "http",
        "https"
    )


# =========================================================
# MAIN HTTP ANALYSIS
# =========================================================

def analisar_http(
    host,
    porta
):
    """
    Analisa HTTP e HTTPS de uma porta.

    Retorna sempre:

    {
        "http": {...} | None,
        "https": {...} | None
    }

    Em portas HTTP:

        HTTP é tentado primeiro.

    Se HTTP funcionar:
        não duplica a análise HTTPS.

    Se HTTP falhar por timeout:
        não duplica a espera.

    Em portas TLS:
        HTTPS é tentado primeiro.
    """

    resultado = {

        "http": None,

        "https": None,
    }

    try:

        porta_n = int(
            porta
        )

    except (
        TypeError,
        ValueError
    ):

        porta_n = None

    protocolos = (
        protocolos_para_porta(
            porta
        )
    )

    # =====================================================
    # PORTAS HTTP
    # =====================================================

    if porta_n in (
        80,
        8080,
        8000,
        8081,
        8888,
        3000,
        5000
    ):

        resultado[
            "http"
        ] = analisar_url(
            host,
            porta,
            "http"
        )

        http_ok = (

            isinstance(
                resultado["http"],
                dict
            )

            and (

                resultado[
                    "http"
                ].get(
                    "reachable"
                ) is True

                or

                resultado[
                    "http"
                ].get(
                    "status_code"
                ) is not None
            )
        )

        if http_ok:
            return resultado

        erro_http = str(

            (
                resultado[
                    "http"
                ]
                or {}
            ).get(
                "error"
            )
            or ""

        ).lower()

        # Timeout em porta HTTP:
        # não duplica a espera com HTTPS.

        if (
            "timed out"
            in erro_http
            or
            "timeout"
            in erro_http
        ):

            return resultado

        resultado[
            "https"
        ] = analisar_url(
            host,
            porta,
            "https"
        )

        return resultado

    # =====================================================
    # DEMAIS PORTAS
    # =====================================================

    for protocolo in protocolos:

        resultado[
            protocolo
        ] = analisar_url(
            host,
            porta,
            protocolo
        )

    return resultado