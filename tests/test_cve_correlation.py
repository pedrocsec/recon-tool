import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.cve_correlation import montar_cpe_base
from modules.crtsh import alvo_local, enumerar_subdominios


def test_cpe_apache():
    esperado = "cpe:2.3:a:apache:http_server:2.4.29:*:*:*:*:*:*:*"
    assert montar_cpe_base("Apache", "2.4.29") == esperado


def test_cpe_apache_aliases():
    esperado = "cpe:2.3:a:apache:http_server:2.4.29:*:*:*:*:*:*:*"
    assert montar_cpe_base("Apache HTTP Server", "2.4.29") == esperado
    assert montar_cpe_base("httpd", "2.4.29") == esperado


def test_alvos_locais():
    assert alvo_local("localhost")
    assert alvo_local("api.localhost")
    assert alvo_local("127.0.0.1")
    assert alvo_local("192.168.1.10")
    assert not alvo_local("example.com")


def test_localhost_nao_consulta_crtsh(monkeypatch):
    def falhar(*args, **kwargs):
        raise AssertionError("crt.sh não deveria ser consultado para localhost")

    import modules.crtsh as crtsh
    monkeypatch.setattr(crtsh, "consultar_crtsh", falhar)

    assert enumerar_subdominios("localhost") == ["localhost"]


if __name__ == "__main__":
    test_cpe_apache()
    test_cpe_apache_aliases()
    test_alvos_locais()

    # Execução manual sem pytest: monkeypatch simples.
    import modules.crtsh as crtsh
    original = crtsh.consultar_crtsh
    crtsh.consultar_crtsh = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("crt.sh não deveria ser consultado para localhost")
    )
    try:
        assert enumerar_subdominios("localhost") == ["localhost"]
    finally:
        crtsh.consultar_crtsh = original

    print("OK: testes locais de CPE e alvo local passaram")
