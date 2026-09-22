"""
Recon Tool — Display 3.7

Apenas representa os dados reais do resultado.
Não recalcula métricas de intelligence.
"""


def linha():
    print("=" * 58)


def titulo(texto):
    print()
    linha()
    print(f"           {texto}")
    linha()


def status_host(status):
    if status == "resolved":
        return "✅ Online / DNS resolvido"

    return "⚠️ DNS não resolveu"


def explicar_porta(porta):
    service = porta.get("service_guess")

    if service:
        return f"🟢 {porta['port']:<5} {service}"

    return f"🟢 {porta['port']:<5} TCP aberto / serviço não identificado"


def explicar_status_http(status_code, status):
    if status_code is None:
        return "⚪ Status desconhecido"

    if status_code >= 500:
        return f"🔴 {status_code} {status}"

    if status_code >= 400:
        return f"🟡 {status_code} {status}"

    if status_code >= 300:
        return f"↪️ {status_code} {status}"

    if status_code >= 200:
        return f"🟢 {status_code} {status}"

    return f"⚪ {status_code} {status}"


def explicar_http(dados):
    if not isinstance(dados, dict):
        return "⚪ HTTP/HTTPS não identificado"

    if dados.get("service") == "unknown":
        return "⚪ HTTP/HTTPS não identificado"

    protocolo = dados.get("protocol")

    if not isinstance(protocolo, str) or not protocolo:
        protocolo = "?"
    else:
        protocolo = protocolo.upper()

    status_code = dados.get("status_code")
    status = dados.get("status") or "Status desconhecido"

    status_formatado = explicar_status_http(status_code, status)

    resultado = f"{protocolo} → {status_formatado}"

    titulo_pagina = dados.get("title")

    if titulo_pagina:
        resultado += f" → {titulo_pagina}"

    redirect_count = dados.get("redirect_count", 0) or 0

    if redirect_count > 0:
        resultado += f" → {redirect_count} redirect"
        if redirect_count != 1:
            resultado += "s"

    return resultado


def explicar_erro_http(dados):
    if not isinstance(dados, dict):
        return None

    erro = dados.get("error")

    if not erro:
        return None

    return f"⚪ {erro}"


def resposta_visivel(resposta):
    if not isinstance(resposta, dict):
        return False

    if resposta.get("reachable") is True:
        return True

    return resposta.get("status_code") is not None


def extrair_respostas_porta(http):
    """
    Extrai respostas do schema oficial aninhado:

        { "http": {...}, "https": {...} }

    Compatível com schema plano legado.
    """
    if not isinstance(http, dict) or not http:
        return []

    http_aninhado = http.get("http")
    https_aninhado = http.get("https")

    formato_aninhado = (
        isinstance(http_aninhado, dict)
        or isinstance(https_aninhado, dict)
        or ("http" in http)
        or ("https" in http)
    )

    respostas = []

    if formato_aninhado:
        if isinstance(http_aninhado, dict):
            respostas.append(http_aninhado)

        if isinstance(https_aninhado, dict):
            respostas.append(https_aninhado)
    else:
        respostas.append(http)

    return [r for r in respostas if resposta_visivel(r)]


def mostrar_host(host, dados):
    print()
    print("-" * 58)
    print(f"🖥️  {host}")
    print("-" * 58)

    # STATUS
    print()
    print("STATUS:")
    print(status_host(dados.get("status")))

    # IP
    ip_info = dados.get("ip") or {}

    print()
    print("🌐 IP:")

    ipv4 = ip_info.get("ipv4") or []
    ipv6 = ip_info.get("ipv6") or []

    if ipv4:
        for ip in ipv4:
            print(f"   IPv4: {ip}")
    else:
        print("   IPv4: não encontrado")

    if ipv6:
        for ip in ipv6:
            print(f"   IPv6: {ip}")

    cname = ip_info.get("cname")

    if cname:
        print(f"   CNAME/FQDN: {cname}")

    # PORTAS
    print()
    print("🔌 PORTAS ABERTAS:")

    portas = dados.get("ports") or []

    if not portas:
        print("   Nenhuma porta aberta encontrada.")
    else:
        for porta in portas:
            if not isinstance(porta, dict):
                continue
            print("   " + explicar_porta(porta))

    # HTTP / HTTPS
    print()
    print("🌍 HTTP / HTTPS:")

    encontrou_http = False

    for porta in portas:
        if not isinstance(porta, dict):
            continue

        http = porta.get("http")

        if http is None or not isinstance(http, dict) or not http:
            continue

        respostas_visiveis = extrair_respostas_porta(http)

        if not respostas_visiveis:
            # Houve tentativa, mas nenhuma resposta confirmada
            continue

        encontrou_http = True
        numero = porta.get("port")

        print(f"   Porta {numero}:")

        for resposta in respostas_visiveis:
            print("      " + explicar_http(resposta))

            if resposta.get("redirected", False):
                destino = (
                    resposta.get("redirect_target")
                    or resposta.get("final_url")
                )
                if destino:
                    print(f"         ↪️ Destino: {destino}")

            elif resposta.get("redirect_count", 0):
                destino = resposta.get("final_url")
                if destino:
                    print(f"         ↪️ Destino: {destino}")

            if resposta.get("https_confirmed", False) or (
                resposta.get("protocol") == "https"
                and resposta.get("reachable")
            ):
                print("         🔐 HTTPS confirmado")

            headers = resposta.get("headers") or {}

            if not isinstance(headers, dict):
                headers = {}

            content_type = (
                resposta.get("content_type")
                or headers.get("content-type")
                or headers.get("Content-Type")
            )

            if content_type:
                print(f"         📄 Content-Type: {content_type}")

            titulo_resp = str(resposta.get("title") or "").lower()
            http_em_https = (
                resposta.get("protocol") == "http"
                and "plain http request was sent to https" in titulo_resp
            )

            sec = resposta.get("security_headers") or {}

            if (
                isinstance(sec, dict)
                and sec
                and not http_em_https
            ):
                ausentes = [
                    nome for nome, info in sec.items()
                    if isinstance(info, dict) and not info.get("presente")
                ]
                presentes = [
                    nome for nome, info in sec.items()
                    if isinstance(info, dict) and info.get("presente")
                ]

                if presentes:
                    print(
                        "         🛡️ Headers presentes: "
                        + ", ".join(presentes)
                    )

                if ausentes:
                    print(
                        "         ⚠️ Headers ausentes: "
                        + ", ".join(ausentes)
                    )

            erro = explicar_erro_http(resposta)

            if erro:
                print(f"         {erro}")

    if not encontrou_http:
        print("   Nenhuma resposta HTTP/HTTPS confirmada.")

    # TECNOLOGIAS
    print()
    print("🔎 TECNOLOGIAS:")

    tecnologias = dados.get("technologies") or []

    if not tecnologias:
        print("   Nenhuma tecnologia identificada.")
    else:
        for tecnologia in tecnologias:
            if not isinstance(tecnologia, dict):
                continue

            nome = tecnologia.get("name", "?")
            versao = tecnologia.get("version")
            source = tecnologia.get("source", "?")
            evidence = tecnologia.get("evidence", "")

            if versao:
                texto = f"   • {nome} {versao}"
            else:
                texto = f"   • {nome}"

            print(texto)
            print(f"     Fonte: {source}")

            if evidence:
                print(f"     Evidência: {evidence}")


def mostrar_resumo(resultado):
    summary = resultado.get("summary") or {}
    intelligence = resultado.get("intelligence") or {}
    exposure = intelligence.get("exposure") or {}

    titulo("📊 RESUMO DO RECON")

    print(f"🎯 Alvo: {resultado.get('target', '?')}")

    if resultado.get("version"):
        print(f"📦 Versão: {resultado.get('version')}")

    print()
    print(f"🌐 Hosts encontrados: {summary.get('total_hosts', 0)}")
    print(f"✅ Hosts resolvidos: {summary.get('resolved_hosts', 0)}")
    print(f"⚠️ Hosts não resolvidos: {summary.get('unresolved_hosts', 0)}")
    print(f"🔌 Portas abertas: {summary.get('total_open_ports', 0)}")

    web_services = exposure.get("web_services")
    if web_services is None:
        web_services = summary.get("web_services", 0)

    web_observations = exposure.get("web_observations")
    if web_observations is None:
        web_observations = summary.get("web_observations", 0)

    print(f"🌍 Serviços web: {web_services}")
    print(f"📡 Observações HTTP/HTTPS: {web_observations}")

    print(f"🔎 Tecnologias: {summary.get('total_technologies', 0)}")
    print()

    scan = resultado.get("scan") or {}
    duracao = scan.get("duration_seconds", 0) or 0

    print(f"⏱️ Duração: {duracao:.2f}s")
    print()
    print("💾 Relatório completo: resultado.json")


def mostrar_resultado(resultado):
    titulo("RECON TOOL — RESULTADO")

    hosts = resultado.get("hosts") or {}

    for host, dados in hosts.items():
        if not isinstance(dados, dict):
            continue

        mostrar_host(host, dados)

    mostrar_resumo(resultado)

    print()
    linha()
