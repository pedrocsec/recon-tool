# Recon Tool 4.1.2 — pacote corrigido

## Correções desta versão

1. `modules/` é preservado como pacote Python.
2. Foi adicionada uma suíte mínima de testes em `tests/`.
3. O CPE do Apache 2.4.29 é gerado como:
   `cpe:2.3:a:apache:http_server:2.4.29:*:*:*:*:*:*:*`
4. `Apache HTTP Server`, `Apache HTTPD` e `httpd` usam o mesmo perfil CPE.
5. Alvos `localhost`, `*.localhost` e IPs locais/privados não consultam o `crt.sh`.
   Isso evita os 17 falsos hosts observados no teste anterior.
6. O fallback do crt.sh continua disponível para domínios públicos quando a consulta falhar.

## Testes locais

```bash
python3 tests/test_cve_correlation.py
python3 tests/test_imports.py
```

Para o mock local:

```bash
python3 mock_server.py
```

Em outro terminal:

```bash
curl -i http://localhost:8080
python3 main.py localhost
```

A execução com `localhost` deve analisar somente `localhost`, não os subdomínios falsos retornados pelo crt.sh.

## Limitação importante

Os testes locais validam importação, normalização/CPE e isolamento do alvo local.
Eles não comprovam uma correlação CVE ao vivo no NVD. Essa parte depende de rede, rate limit e disponibilidade da API do NVD.
