# Recon Tool 4.1.3

Ferramenta de reconnaissance desenvolvida em Python para automatizar etapas iniciais de análise de superfície de ataque em alvos autorizados.

O projeto foi desenvolvido para aprendizado em cibersegurança, laboratórios e avaliações de segurança realizadas com autorização.

## Funcionalidades

A versão 4.1.3 realiza:

- Enumeração de subdomínios através de Certificate Transparency usando `crt.sh`
- Resolução DNS
- Identificação de hosts resolvidos e não resolvidos
- Port scanning básico
- Análise HTTP/HTTPS
- Identificação de serviços web
- Detecção de tecnologias através de evidências HTTP
- Análise de security headers
- Recon Intelligence
- Correlação possível entre tecnologias identificadas e vulnerabilidades do NVD
- Validação da configuração do CVE contra o CPE identificado para reduzir correlações incorretas
- Cache local das consultas de CVE
- Geração de relatório estruturado em JSON

A correlação de CVE representa uma **possibilidade de correspondência**, e não uma confirmação de vulnerabilidade.

## Requisitos

- Python 3.9+
- Conexão com a internet para consultas ao `crt.sh` e NVD
- Dependências listadas em `requirements.txt`

## Instalação

Clone o repositório:

```bash
git clone https://github.com/pedrocsec/recon-tool.git
cd recon-tool
