# Recon Tool 4.1.2

Ferramenta de reconhecimento e análise de superfície de ataque desenvolvida em Python para fins de estudo, laboratórios e avaliações de segurança autorizadas.

## Objetivo

O Recon Tool automatiza etapas iniciais de reconhecimento a partir de um domínio ou alvo autorizado, organizando os resultados em um relatório estruturado.

A versão 4.1.2 reúne:

- Enumeração de subdomínios via Certificate Transparency (`crt.sh`)
- Resolução DNS
- Identificação de hosts acessíveis
- Port scan básico
- Análise HTTP/HTTPS
- Detecção de tecnologias
- Análise de security headers
- Recon Intelligence
- Correlação possível entre tecnologias e CVEs via NVD
- Priorização heurística de risco
- Geração de relatório em Markdown
- Geração de resultado completo em JSON

## Estrutura

```text
recon-tool-v4.1.2-fixed/
├── main.py
├── mock_server.py
├── modules/
│   ├── asset.py
│   ├── crtsh.py
│   ├── cve_correlation.py
│   ├── display.py
│   ├── dns.py
│   ├── enumerator.py
│   ├── http.py
│   ├── intelligence.py
│   ├── ports.py
│   ├── portscan.py
│   ├── reporter.py
│   ├── risk_score.py
│   ├── security_headers.py
│   ├── techdetect.py
│   └── technology.py
└── tests/
    ├── test_cve_correlation.py
    └── test_imports.py