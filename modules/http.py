import warnings
import time
import requests
import urllib3


# ==========================================================
# CONFIGURAÇÃO
# ==========================================================

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

warnings.filterwarnings(
    "ignore",
    message=".*LibreSSL.*",
    category=Warning
)


USER_AGENT = "ReconTool/3.1"

DEFAULT_TIMEOUT = 8

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


# ==========================================================
# HTML
# ==========================================================

def extrair_titulo(html):
    """
    Extrai o conteúdo da tag <title>.
    """

    if not html:
        return None

    html_lower = html.lower()

    inicio = html_lower.find("<title")

    if inicio == -1:
        return None

    inicio = html_lower.find(">", inicio)

    if inicio == -1:
        return None

    fim = html_lower.find("</title>", inicio)

    if fim == -1:
        return None

    titulo = html[inicio + 1:fim]

    titulo = " ".join(
        titulo.split()
    )

    if not titulo:
        return None

    return titulo[:200]


# ==========================================================
# COOKIES
# ==========================================================

def analisar_cookies(resposta):
    """
    Analisa atributos básicos dos cookies recebidos.
    """

    cookies = []

    for cookie in resposta.cookies:
        cookies.append({
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": "HttpOnly" in cookie._rest,
            "samesite": cookie._rest.get("SameSite")
        })

    return cookies


# ==========================================================
# SECURITY HEADERS
# ==========================================================

def analisar_security_headers(headers):
    """
    Verifica headers de segurança comuns.
    """

    resultado = {}

    for header, nome in SECURITY_HEADERS.items():

        valor = headers.get(header)

        resultado[nome] = {
            "presente": valor is not None,
            "valor": valor
        }

    return resultado


# ==========================================================
# TECHNOLOGY DETECTION
# ==========================================================

def detectar_tecnologias(headers, html):
    """
    Detecta tecnologias através de evidências observáveis.
    """

    tecnologias = []

    server = headers.get(
        "Server",
        ""
    )

    powered = headers.get(
        "X-Powered-By",
        ""
    )

    server_lower = server.lower()

    powered_lower = powered.lower()

    html_lower = (
        html.lower()
        if html
        else ""
    )


    # ------------------------------------------------------
    # CLOUDFLARE
    # ------------------------------------------------------

    if (
        "cloudflare" in server_lower
        or headers.get("CF-Ray")
        or headers.get("CF-Cache-Status")
    ):

        tecnologias.append({
            "name": "Cloudflare",
            "version": None,
            "source": "HTTP headers",
            "evidence": (
                server
                or "CF-* header detectado"
            )
        })


    # ------------------------------------------------------
    # NGINX
    # ------------------------------------------------------

    if "nginx" in server_lower:

        tecnologias.append({
            "name": "Nginx",
            "version": None,
            "source": "Server",
            "evidence": server
        })


    # ------------------------------------------------------
    # APACHE
    # ------------------------------------------------------

    if "apache" in server_lower:

        tecnologias.append({
            "name": "Apache",
            "version": None,
            "source": "Server",
            "evidence": server
        })


    # ------------------------------------------------------
    # IIS
    # ------------------------------------------------------

    if "microsoft-iis" in server_lower:

        tecnologias.append({
            "name": "Microsoft IIS",
            "version": None,
            "source": "Server",
            "evidence": server
        })


    # ------------------------------------------------------
    # PHP
    # ------------------------------------------------------

    if "php" in powered_lower:

        tecnologias.append({
            "name": "PHP",
            "version": None,
            "source": "X-Powered-By",
            "evidence": powered
        })


    # ------------------------------------------------------
    # ASP.NET
    # ------------------------------------------------------

    if "asp.net" in powered_lower:

        tecnologias.append({
            "name": "ASP.NET",
            "version": None,
            "source": "X-Powered-By",
            "evidence": powered
        })


    # ------------------------------------------------------
    # WORDPRESS
    # ------------------------------------------------------

    if (
        "wp-content" in html_lower
        or "wp-includes" in html_lower
        or "wordpress" in html_lower
    ):

        tecnologias.append({
            "name": "WordPress",
            "version": None,
            "source": "HTML",
            "evidence": (
                "Padrão WordPress encontrado no HTML"
            )
        })


    # ------------------------------------------------------
    # REACT
    # ------------------------------------------------------

    if (
        "react" in html_lower
        or "data-reactroot" in html_lower
        or "__next_data__" in html_lower
        or "__next" in html_lower
    ):

        tecnologias.append({
            "name": "React/Next.js",
            "version": None,
            "source": "HTML",
            "evidence": (
                "Padrão React/Next.js encontrado"
            )
        })


    # ------------------------------------------------------
    # BOOTSTRAP
    # ------------------------------------------------------

    if "bootstrap" in html_lower:

        tecnologias.append({
            "name": "Bootstrap",
            "version": None,
            "source": "HTML",
            "evidence": (
                "Referência a Bootstrap encontrada"
            )
        })


    return tecnologias


# ==========================================================
# SERVIÇO WEB
# ==========================================================

def identificar_servico(content_type):
    """
    Tenta identificar o tipo de serviço baseado
    no Content-Type.
    """

    if not content_type:
        return None

    content_type_lower = content_type.lower()

    if "text/html" in content_type_lower:
        return "web"

    if "application/json" in content_type_lower:
        return "api/json"

    if "xml" in content_type_lower:
        return "xml"

    if "javascript" in content_type_lower:
        return "javascript"

    if "css" in content_type_lower:
        return "css"

    if "image/" in content_type_lower:
        return "image"

    return "unknown"


# ==========================================================
# STATUS
# ==========================================================

def classificar_status(status_code):
    """
    Classifica o status HTTP.
    """

    if status_code is None:
        return "unknown"

    if 200 <= status_code < 300:
        return "success"

    if 300 <= status_code < 400:
        return "redirect"

    if 400 <= status_code < 500:
        return "client_error"

    if 500 <= status_code < 600:
        return "server_error"

    return "unknown"


# ==========================================================
# URL
# ==========================================================

def analisar_url(
    url,
    timeout=DEFAULT_TIMEOUT
):
    """
    Analisa uma URL específica.
    """

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": (
            "text/html,"
            "application/xhtml+xml,"
            "application/json,"
            "*/*"
        )
    }

    inicio = time.perf_counter()

    try:

        resposta = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )

        tempo_ms = round(
            (time.perf_counter() - inicio) * 1000,
            2
        )

        titulo = extrair_titulo(
            resposta.text
        )

        headers_dict = dict(
            resposta.headers
        )

        security_headers = (
            analisar_security_headers(
                resposta.headers
            )
        )

        cookies = analisar_cookies(
            resposta
        )

        tecnologias = detectar_tecnologias(
            resposta.headers,
            resposta.text
        )

        # --------------------------------------------------
        # REDIRECTS
        # --------------------------------------------------

        redirects = []

        for redirect in resposta.history:

            redirects.append({
                "status_code": redirect.status_code,
                "url": redirect.url,
                "location": redirect.headers.get(
                    "Location"
                )
            })


        # --------------------------------------------------
        # CONTENT TYPE
        # --------------------------------------------------

        content_type = resposta.headers.get(
            "Content-Type"
        )


        # --------------------------------------------------
        # SERVIÇO
        # --------------------------------------------------

        servico = identificar_servico(
            content_type
        )


        # --------------------------------------------------
        # PROTOCOLO
        # --------------------------------------------------

        protocolo = (
            "https"
            if url.lower().startswith("https://")
            else "http"
        )


        # --------------------------------------------------
        # RESULTADO
        # --------------------------------------------------

        return {

            "reachable": True,

            "protocol": protocolo,

            "status_code": resposta.status_code,

            "status_class": classificar_status(
                resposta.status_code
            ),

            "title": titulo,

            "service": servico,

            "content_type": content_type,

            "server": resposta.headers.get(
                "Server"
            ),

            "x_powered_by": resposta.headers.get(
                "X-Powered-By"
            ),

            "via": resposta.headers.get(
                "Via"
            ),

            "cf_ray": resposta.headers.get(
                "CF-Ray"
            ),

            "cf_cache_status": resposta.headers.get(
                "CF-Cache-Status"
            ),

            "initial_url": url,

            "final_url": resposta.url,

            "redirects": redirects,

            "redirect_count": len(
                resposta.history
            ),

            "https": resposta.url.startswith(
                "https://"
            ),

            "content_length": len(
                resposta.content
            ),

            "response_time_ms": tempo_ms,

            "headers": headers_dict,

            "security_headers": security_headers,

            "cookies": cookies,

            "technologies": tecnologias

        }


    except requests.exceptions.Timeout as erro:

        tempo_ms = round(
            (time.perf_counter() - inicio) * 1000,
            2
        )

        return {

            "reachable": False,

            "protocol": (
                "https"
                if url.lower().startswith("https://")
                else "http"
            ),

            "status_code": None,

            "status_class": "timeout",

            "title": None,

            "service": None,

            "content_type": None,

            "server": None,

            "x_powered_by": None,

            "via": None,

            "cf_ray": None,

            "cf_cache_status": None,

            "initial_url": url,

            "final_url": None,

            "redirects": [],

            "redirect_count": 0,

            "https": url.lower().startswith(
                "https://"
            ),

            "content_length": 0,

            "response_time_ms": tempo_ms,

            "headers": {},

            "security_headers": {
                nome: {
                    "presente": False,
                    "valor": None
                }
                for nome in SECURITY_HEADERS.values()
            },

            "cookies": [],

            "technologies": [],

            "error": (
                f"Timeout após {timeout}s"
            )

        }


    except requests.exceptions.RequestException as erro:

        tempo_ms = round(
            (time.perf_counter() - inicio) * 1000,
            2
        )

        return {

            "reachable": False,

            "protocol": (
                "https"
                if url.lower().startswith("https://")
                else "http"
            ),

            "status_code": None,

            "status_class": "error",

            "title": None,

            "service": None,

            "content_type": None,

            "server": None,

            "x_powered_by": None,

            "via": None,

            "cf_ray": None,

            "cf_cache_status": None,

            "initial_url": url,

            "final_url": None,

            "redirects": [],

            "redirect_count": 0,

            "https": url.lower().startswith(
                "https://"
            ),

            "content_length": 0,

            "response_time_ms": tempo_ms,

            "headers": {},

            "security_headers": {
                nome: {
                    "presente": False,
                    "valor": None
                }
                for nome in SECURITY_HEADERS.values()
            },

            "cookies": [],

            "technologies": [],

            "error": str(erro)

        }


# ==========================================================
# ANALISAR HOST + PORTA
# ==========================================================

def analisar_http(
    host,
    porta=None,
    timeout=DEFAULT_TIMEOUT
):
    """
    Analisa HTTP/HTTPS em uma porta específica.

    Exemplos:

        analisar_http("example.com", 80)
        analisar_http("example.com", 443)
        analisar_http("example.com", 8080)
        analisar_http("example.com", 8443)
    """

    # ------------------------------------------------------
    # PORTA NÃO INFORMADA
    # ------------------------------------------------------

    if porta is None:

        resultado = {
            "http": analisar_url(
                f"http://{host}",
                timeout
            ),

            "https": analisar_url(
                f"https://{host}",
                timeout
            )
        }

        return resultado


    # ------------------------------------------------------
    # PORTA 80
    # ------------------------------------------------------

    if porta == 80:

        return {
            "http": analisar_url(
                f"http://{host}:80",
                timeout
            ),
            "https": None
        }


    # ------------------------------------------------------
    # PORTA 443
    # ------------------------------------------------------

    if porta == 443:

        return {
            "http": None,
            "https": analisar_url(
                f"https://{host}:443",
                timeout
            )
        }


    # ------------------------------------------------------
    # PORTA 8080
    # ------------------------------------------------------

    if porta == 8080:

        return {
            "http": analisar_url(
                f"http://{host}:8080",
                timeout
            ),
            "https": None
        }


    # ------------------------------------------------------
    # PORTA 8443
    # ------------------------------------------------------

    if porta == 8443:

        return {
            "http": None,
            "https": analisar_url(
                f"https://{host}:8443",
                timeout
            )
        }


    # ------------------------------------------------------
    # OUTRAS PORTAS
    #
    # Primeiro tenta HTTP.
    # ------------------------------------------------------

    http_resultado = analisar_url(
        f"http://{host}:{porta}",
        timeout
    )

    https_resultado = analisar_url(
        f"https://{host}:{porta}",
        timeout
    )

    return {
        "http": http_resultado,
        "https": https_resultado
    }