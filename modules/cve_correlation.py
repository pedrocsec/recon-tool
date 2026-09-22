import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


VERSION = "4.1.3"

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_CACHE_FILE = "cve_cache.json"
REQUEST_TIMEOUT = 25

NO_KEY_INTERVAL = 6.1
API_KEY_INTERVAL = 0.7

WARNING = (
    "CORRELAÇÃO POSSÍVEL — baseada em tecnologia/versão detectada "
    "e em dados do NVD. Não constitui confirmação de vulnerabilidade."
)


TECH_CPE_PROFILES = {
    "apache": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "php": ("php", "php"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"),
}


def agora_utc():
    return datetime.now(timezone.utc).isoformat()


def normalizar_texto(valor):
    if valor is None:
        return ""

    return " ".join(
        str(valor).strip().split()
    )


def carregar_cache(caminho):
    caminho = Path(caminho)

    if not caminho.exists():
        return {
            "version": VERSION,
            "updated_at": None,
            "cpe_resolution": {},
            "cve_queries": {},
        }

    try:
        with caminho.open(
            "r",
            encoding="utf-8",
        ) as arquivo:
            cache = json.load(arquivo)

    except (
        OSError,
        json.JSONDecodeError,
    ):
        cache = {}

    if not isinstance(
        cache,
        dict,
    ):
        cache = {}

    cache.setdefault(
        "version",
        VERSION,
    )

    cache.setdefault(
        "updated_at",
        None,
    )

    cache.setdefault(
        "cpe_resolution",
        {},
    )

    cache.setdefault(
        "cve_queries",
        {},
    )

    return cache


def salvar_cache(
    caminho,
    cache,
):
    caminho = Path(caminho)

    caminho.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    cache["version"] = VERSION
    cache["updated_at"] = agora_utc()

    temporario = caminho.with_suffix(
        caminho.suffix + ".tmp"
    )

    with temporario.open(
        "w",
        encoding="utf-8",
    ) as arquivo:
        json.dump(
            cache,
            arquivo,
            indent=4,
            ensure_ascii=False,
        )

    temporario.replace(caminho)


def escapar_componente_cpe(valor):
    """
    Escapa somente caracteres especiais
    pertencentes ao componente do CPE.

    IMPORTANTE:
    os ':' que separam os componentes
    do CPE NÃO devem ser escapados aqui.
    """

    texto = str(
        valor or ""
    ).strip().lower()

    texto = texto.replace(
        "\\",
        "\\\\",
    )

    texto = texto.replace(
        ":",
        "\\:",
    )

    return texto


def montar_cpe_base(
    technology,
    version,
):
    nome = normalizar_texto(
        technology
    ).lower()

    versao = normalizar_texto(
        version
    )

    if not nome:
        return None

    if not versao:
        versao = "*"

    perfil = TECH_CPE_PROFILES.get(
        nome
    )

    if not perfil:
        return None

    vendor, product = perfil

    return (
        "cpe:2.3:a:"
        f"{escapar_componente_cpe(vendor)}:"
        f"{escapar_componente_cpe(product)}:"
        f"{escapar_componente_cpe(versao)}:"
        "*:*:*:*:*:*:*"
    )


def normalizar_cpe_para_cve_api(cpe):
    """
    Normaliza o CPE antes de enviá-lo para
    a CVE API do NVD.

    A CPE API pode retornar componentes
    com escaping. A CVE API espera o
    CPE 2.3 em sua forma de consulta.

    Exemplo:

        cpe:2.3\:a:php\:php:7.2.24:\*...

    vira:

        cpe:2.3:a:php:php:7.2.24:*...
    """

    if not isinstance(
        cpe,
        str,
    ):
        return cpe

    texto = cpe.strip()

    if not texto:
        return texto

    # Primeiro desfaz escaping duplicado.
    texto = texto.replace(
        "\\\\",
        "\\",
    )

    # O CPE retornado pela API pode trazer
    # os separadores ':' escapados.
    #
    # Para os CPEs produzidos pelos perfis
    # deste projeto, os componentes são
    # simples e podemos normalizar os
    # separadores diretamente.
    texto = texto.replace(
        "\\:",
        ":",
    )

    # Alguns retornos podem representar '*'
    # com escape. A CVE API espera o wildcard
    # normal.
    texto = texto.replace(
        "\\*",
        "*",
    )

    return texto


def montar_cpe_match_string(
    technology,
    version,
):
    return montar_cpe_base(
        technology,
        version,
    )


class RateLimiter:

    def __init__(
        self,
        api_key=None,
    ):
        self.interval = (
            API_KEY_INTERVAL
            if api_key
            else NO_KEY_INTERVAL
        )

        self.ultimo_request = 0.0

    def esperar(self):
        agora = time.monotonic()

        espera = (
            self.interval
            - (
                agora
                - self.ultimo_request
            )
        )

        if espera > 0:
            time.sleep(
                espera
            )

        self.ultimo_request = (
            time.monotonic()
        )


def cabecalhos(
    api_key=None,
):
    headers = {
        "Accept": "application/json",
        "User-Agent": (
            f"ReconTool/{VERSION} "
            "(authorized-security-testing)"
        ),
    }

    if api_key:
        headers["apiKey"] = api_key

    return headers


def requisicao_json(
    url,
    params,
    api_key,
    limiter,
):
    for tentativa in range(3):

        limiter.esperar()

        try:
            resposta = requests.get(
                url,
                params=params,
                headers=cabecalhos(
                    api_key
                ),
                timeout=REQUEST_TIMEOUT,
            )

        except requests.RequestException as erro:

            if tentativa < 2:
                time.sleep(
                    2 * (
                        tentativa + 1
                    )
                )

                continue

            return (
                None,
                f"Erro de rede: {erro}",
            )

        if resposta.status_code == 200:

            try:
                return (
                    resposta.json(),
                    None,
                )

            except ValueError as erro:
                return (
                    None,
                    (
                        "JSON inválido retornado "
                        f"pelo NVD: {erro}"
                    ),
                )

        if resposta.status_code in (
            403,
            429,
        ):

            retry_after = (
                resposta.headers.get(
                    "Retry-After"
                )
            )

            try:
                espera = float(
                    retry_after
                )

            except (
                TypeError,
                ValueError,
            ):
                espera = (
                    15.0
                    if resposta.status_code == 429
                    else 10.0
                )

            if tentativa < 2:
                time.sleep(
                    max(
                        espera,
                        1.0,
                    )
                )

                continue

            return (
                None,
                (
                    "NVD recusou a requisição "
                    f"({resposta.status_code}). "
                    "Verifique rate limit e API key."
                ),
            )

        trecho = normalizar_texto(
            resposta.text
        )[:300]

        return (
            None,
            (
                f"NVD HTTP "
                f"{resposta.status_code}: "
                f"{trecho}"
            ),
        )

    return (
        None,
        "Falha desconhecida ao consultar NVD.",
    )


def extrair_cpe_nomes(
    payload,
):
    """
    Extrai CPE Names do retorno da NVD CPE API.
    """

    resultados = []

    if not isinstance(
        payload,
        dict,
    ):
        return resultados

    produtos = (
        payload.get(
            "products"
        )
        or []
    )

    for produto in produtos:

        if not isinstance(
            produto,
            dict,
        ):
            continue

        cpe_obj = produto.get(
            "cpe"
        )

        if not isinstance(
            cpe_obj,
            dict,
        ):
            continue

        nomes = cpe_obj.get(
            "cpeName"
        )

        if isinstance(
            nomes,
            str,
        ):
            nomes_iteraveis = [
                nomes
            ]

        elif isinstance(
            nomes,
            list,
        ):
            nomes_iteraveis = nomes

        else:
            nomes_iteraveis = []

        for nome_obj in nomes_iteraveis:

            if isinstance(
                nome_obj,
                str,
            ):
                nome = nome_obj

            elif isinstance(
                nome_obj,
                dict,
            ):
                nome = nome_obj.get(
                    "cpeName"
                )

            else:
                continue

            if (
                isinstance(
                    nome,
                    str,
                )
                and nome
                and nome not in resultados
            ):
                resultados.append(
                    nome
                )

    return resultados


def resolver_cpe(
    technology,
    version,
    cache,
    api_key,
    limiter,
    stats,
):
    nome = normalizar_texto(
        technology
    )

    versao = normalizar_texto(
        version
    )

    chave = (
        f"{nome.lower()}|{versao}"
    )

    cached = (
        cache[
            "cpe_resolution"
        ].get(
            chave
        )
    )

    if (
        isinstance(
            cached,
            dict,
        )
        and cached.get(
            "status"
        )
        != "erro"
    ):
        stats[
            "cache_hits"
        ] += 1

        return cached

    cpe_match = (
        montar_cpe_match_string(
            nome,
            versao,
        )
    )

    if not cpe_match:

        resultado = {
            "status": (
                "nao_mapeado"
            ),
            "cpe": None,
            "metodo": (
                "perfil_cpe_nao_disponivel"
            ),
        }

        stats[
            "cpes_nao_encontrados"
        ] += 1

        cache[
            "cpe_resolution"
        ][chave] = resultado

        return resultado

    payload, erro = (
        requisicao_json(
            NVD_CPE_URL,
            {
                "cpeMatchString": cpe_match,
                "resultsPerPage": 100,
            },
            api_key,
            limiter,
        )
    )

    if erro:

        stats[
            "cpe_erros"
        ] += 1

        return {
            "status": "erro",
            "cpe": None,
            "erro": erro,
            "metodo": (
                "cpe_dictionary_lookup"
            ),
        }

    nomes = extrair_cpe_nomes(
        payload
    )

    if versao == "*":

        candidatos_exatos = nomes

    else:

        marcador_versao = (
            f":{versao}:"
        )

        candidatos_exatos = [
            item
            for item in nomes
            if marcador_versao in item
        ]

    escolhido = (
        candidatos_exatos[0]
        if candidatos_exatos
        else None
    )

    if escolhido:

        resultado = {
            "status": "resolvido",
            "cpe": escolhido,
            "metodo": (
                "cpe_dictionary_lookup"
            ),
        }

        stats[
            "cpes_resolvidos"
        ] += 1

    else:

        resultado = {
            "status": (
                "nao_encontrado"
            ),
            "cpe": None,
            "metodo": (
                "cpe_dictionary_lookup"
            ),
        }

        stats[
            "cpes_nao_encontrados"
        ] += 1

    cache[
        "cpe_resolution"
    ][chave] = resultado

    return resultado


def extrair_cvss(
    cve,
):
    metricas_por_versao = [
        (
            "4.0",
            "cvssMetricV40",
        ),
        (
            "3.1",
            "cvssMetricV31",
        ),
        (
            "3.0",
            "cvssMetricV30",
        ),
        (
            "2.0",
            "cvssMetricV2",
        ),
    ]

    for versao, campo in (
        metricas_por_versao
    ):

        metricas = (
            (
                cve.get(
                    "metrics"
                )
                or {}
            ).get(
                campo,
                [],
            )
            or []
        )

        if not isinstance(
            metricas,
            list,
        ):
            continue

        metricas = sorted(
            metricas,
            key=lambda item: (
                0
                if (
                    isinstance(
                        item,
                        dict,
                    )
                    and item.get(
                        "type"
                    )
                    == "Primary"
                )
                else 1
            ),
        )

        for metrica in metricas:

            if not isinstance(
                metrica,
                dict,
            ):
                continue

            dados = (
                metrica.get(
                    "cvssData"
                )
                or {}
            )

            if not isinstance(
                dados,
                dict,
            ):
                continue

            score = dados.get(
                "baseScore"
            )

            severity = dados.get(
                "baseSeverity"
            )

            if (
                score is not None
                or severity is not None
            ):
                return {
                    "version": versao,
                    "base_score": score,
                    "severity": severity,
                }

    return {
        "version": None,
        "base_score": None,
        "severity": None,
    }


def extrair_cves(
    payload,
):
    resultados = []

    if not isinstance(
        payload,
        dict,
    ):
        return resultados

    for item in (
        payload.get(
            "vulnerabilities"
        )
        or []
    ):

        if not isinstance(
            item,
            dict,
        ):
            continue

        cve = item.get(
            "cve"
        )

        if not isinstance(
            cve,
            dict,
        ):
            continue

        cve_id = cve.get(
            "id"
        )

        if not cve_id:
            continue

        resultados.append(
            {
                "cve": cve_id,
                "cvss": extrair_cvss(
                    cve
                ),
                "published": (
                    cve.get(
                        "published"
                    )
                ),
                "last_modified": (
                    cve.get(
                        "lastModified"
                    )
                ),
                "nvd_url": (
                    "https://nvd.nist.gov/"
                    f"vuln/detail/{cve_id}"
                ),
                "correlacao": (
                    "possível"
                ),
            }
        )

    def ordenacao(item):
        score = (
            item.get(
                "cvss",
                {},
            ).get(
                "base_score"
            )
        )

        if isinstance(
            score,
            (int, float),
        ):
            return (
                0,
                -float(score),
                item.get(
                    "cve",
                    "",
                ),
            )

        return (
            1,
            0,
            item.get(
                "cve",
                "",
            ),
        )

    resultados.sort(
        key=ordenacao
    )

    return resultados


def consultar_cves_por_cpe(
    cpe,
    cache,
    api_key,
    limiter,
    stats,
):
    """
    Consulta CVEs associadas ao CPE.

    A normalização ocorre ANTES da consulta
    porque o CPE retornado pela CPE API pode
    conter escaping que não deve ser enviado
    diretamente ao parâmetro cpeName da CVE API.
    """

    cpe_original = cpe

    cpe_consulta = (
        normalizar_cpe_para_cve_api(
            cpe
        )
    )

    cached = (
        cache[
            "cve_queries"
        ].get(
            cpe_consulta
        )
    )

    if (
        isinstance(
            cached,
            dict,
        )
        and cached.get(
            "status"
        )
        != "erro"
    ):
        stats[
            "cache_hits"
        ] += 1

        return cached

    payload, erro = (
        requisicao_json(
            NVD_CVE_URL,
            {
                "cpeName": cpe_consulta,
                "resultsPerPage": 2000,
            },
            api_key,
            limiter,
        )
    )

    if erro:

        stats[
            "cve_erros"
        ] += 1

        return {
            "status": "erro",
            "cpe": cpe_consulta,
            "cpe_original": cpe_original,
            "cves_possiveis": [],
            "erro": erro,
        }

    cves = extrair_cves(
        payload
    )

    resultado = {
        "status": "consultado",
        "cpe": cpe_consulta,
        "cpe_original": cpe_original,
        "total_resultados": len(
            cves
        ),
        "cves_possiveis": cves,
    }

    cache[
        "cve_queries"
    ][cpe_consulta] = resultado

    stats[
        "cve_consultas"
    ] += 1

    stats[
        "correlacoes_possiveis"
    ] += len(
        cves
    )

    return resultado


def normalizar_tecnologias(
    tecnologias,
):
    resultado = []
    vistos = set()

    if not isinstance(
        tecnologias,
        list,
    ):
        return resultado

    for tecnologia in tecnologias:

        if not isinstance(
            tecnologia,
            dict,
        ):
            continue

        nome = normalizar_texto(
            tecnologia.get(
                "name"
            )
        )

        versao = normalizar_texto(
            tecnologia.get(
                "version"
            )
        )

        if not nome:
            continue

        if not versao:
            versao = "*"

        chave = (
            nome.lower(),
            versao,
        )

        if chave in vistos:
            continue

        vistos.add(
            chave
        )

        resultado.append(
            {
                "name": nome,
                "version": versao,
            }
        )

    return resultado


def correlacionar_tecnologias(
    tecnologias,
    api_key=None,
    cache_file=DEFAULT_CACHE_FILE,
):
    api_key = (
        api_key
        or os.getenv(
            "NVD_API_KEY"
        )
    )

    cache = carregar_cache(
        cache_file
    )

    limiter = RateLimiter(
        api_key=api_key
    )

    stats = {
        "tecnologias_analisadas": 0,
        "cpes_resolvidos": 0,
        "cpes_nao_encontrados": 0,
        "cpes_consultados": 0,
        "cve_consultas": 0,
        "correlacoes_possiveis": 0,
        "cache_hits": 0,
        "cpe_erros": 0,
        "cve_erros": 0,
    }

    resultados = []

    tecnologias_normalizadas = (
        normalizar_tecnologias(
            tecnologias
        )
    )

    for tecnologia in (
        tecnologias_normalizadas
    ):

        stats[
            "tecnologias_analisadas"
        ] += 1

        nome = tecnologia[
            "name"
        ]

        versao = tecnologia[
            "version"
        ]

        cpe_info = resolver_cpe(
            nome,
            versao,
            cache,
            api_key,
            limiter,
            stats,
        )

        item = {
            "tecnologia": nome,
            "versao_detectada": (
                None
                if versao == "*"
                else versao
            ),
            "versao_utilizada_na_correlacao": (
                versao
            ),
            "cpe": cpe_info.get(
                "cpe"
            ),
            "cpe_status": cpe_info.get(
                "status"
            ),
            "cves_possiveis": [],
            "aviso": WARNING,
        }

        if cpe_info.get(
            "erro"
        ):
            item[
                "erro"
            ] = cpe_info[
                "erro"
            ]

        cpe = cpe_info.get(
            "cpe"
        )

        if cpe:

            stats[
                "cpes_consultados"
            ] += 1

            cve_info = (
                consultar_cves_por_cpe(
                    cpe,
                    cache,
                    api_key,
                    limiter,
                    stats,
                )
            )

            item[
                "cves_possiveis"
            ] = cve_info.get(
                "cves_possiveis",
                [],
            )

            item[
                "consulta_status"
            ] = cve_info.get(
                "status"
            )

            if cve_info.get(
                "erro"
            ):
                item[
                    "erro"
                ] = cve_info[
                    "erro"
                ]

            if cve_info.get(
                "cpe"
            ):
                item[
                    "cpe_utilizado_na_consulta"
                ] = cve_info[
                    "cpe"
                ]

        resultados.append(
            item
        )

    salvar_cache(
        cache_file,
        cache,
    )

    return {
        "version": VERSION,
        "aviso": WARNING,
        "fonte": (
            "NVD CVE API 2.0 + "
            "CPE API 2.0"
        ),
        "api_key_configurada": (
            bool(api_key)
        ),
        "cache_file": str(
            cache_file
        ),
        "stats": stats,
        "correlacoes": resultados,
    }


def correlacionar_resultado(
    resultado,
    api_key=None,
    cache_file=DEFAULT_CACHE_FILE,
):
    hosts = (
        resultado.get(
            "hosts",
            {},
        )
        if isinstance(
            resultado,
            dict,
        )
        else {}
    )

    hosts_saida = {}

    total_cves = 0
    hosts_com_cves = 0
    tecnologias_processadas = 0
    cache_hits = 0
    cpes_consultados = 0

    for host, dados in (
        hosts.items()
    ):

        if not isinstance(
            dados,
            dict,
        ):
            continue

        correlacao = (
            correlacionar_tecnologias(
                dados.get(
                    "technologies"
                )
                or [],
                api_key=api_key,
                cache_file=cache_file,
            )
        )

        stats = (
            correlacao.get(
                "stats"
            )
            or {}
        )

        tecnologias_processadas += (
            stats.get(
                "tecnologias_analisadas",
                0,
            )
        )

        cache_hits += (
            stats.get(
                "cache_hits",
                0,
            )
        )

        cpes_consultados += (
            stats.get(
                "cpes_consultados",
                0,
            )
        )

        possiveis = []

        for item in (
            correlacao.get(
                "correlacoes",
                [],
            )
        ):

            cves = (
                item.get(
                    "cves_possiveis"
                )
                or []
            )

            if not cves:
                continue

            possiveis.append(
                item
            )

            total_cves += len(
                cves
            )

        if possiveis:
            hosts_com_cves += 1

        hosts_saida[host] = {
            "aviso": WARNING,
            "cves_possiveis": (
                possiveis
            ),
            "tecnologias_analisadas": (
                correlacao.get(
                    "correlacoes",
                    [],
                )
            ),
        }

    return {
        "version": VERSION,
        "aviso": WARNING,
        "fonte": (
            "NVD CVE API 2.0 + "
            "CPE API 2.0"
        ),
        "api_key_configurada": bool(
            api_key
            or os.getenv(
                "NVD_API_KEY"
            )
        ),
        "cache_file": str(
            cache_file
        ),
        "hosts_processados": (
            len(hosts_saida)
        ),
        "hosts_com_cves_possiveis": (
            hosts_com_cves
        ),
        "tecnologias_processadas": (
            tecnologias_processadas
        ),
        "cpes_consultados": (
            cpes_consultados
        ),
        "cache_hits": cache_hits,
        "cves_possiveis_total": (
            total_cves
        ),
        "hosts": hosts_saida,
    }


def print_cve_correlation(
    analysis,
):
    print()
    print("=" * 58)

    print(
        "              🧠 RECON CVE CORRELATION "
        f"{VERSION}"
    )

    print("=" * 58)
    print()

    print(
        "⚠️ "
        + analysis.get(
            "aviso",
            WARNING,
        )
    )

    print()

    if analysis.get(
        "api_key_configurada"
    ):
        print(
            "🔑 NVD API key: configurada"
        )
    else:
        print(
            "🔓 NVD API key: não configurada"
        )

    stats = (
        analysis.get(
            "stats"
        )
        or {}
    )

    print()

    print(
        "📦 CVEs em correlação possível: "
        + str(
            stats.get(
                "correlacoes_possiveis",
                0,
            )
        )
    )

    print(
        "🧩 CPEs consultados: "
        + str(
            stats.get(
                "cpes_consultados",
                0,
            )
        )
    )

    print(
        "♻️ Cache hits: "
        + str(
            stats.get(
                "cache_hits",
                0,
            )
        )
    )

    if stats.get(
        "cpe_erros",
        0,
    ):
        print(
            "⚠️ Erros na CPE API: "
            + str(
                stats.get(
                    "cpe_erros",
                    0,
                )
            )
        )

    if stats.get(
        "cve_erros",
        0,
    ):
        print(
            "⚠️ Erros na CVE API: "
            + str(
                stats.get(
                    "cve_erros",
                    0,
                )
            )
        )

    print()
    print("=" * 58)