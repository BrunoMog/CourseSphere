# 🎓 CourseSphere — Plataforma de Recomendação de Cursos
> **Projeto de Avaliação Técnica — Bolsista de Segurança de Aplicações e Confiabilidade (AppSec / SRE)**

CourseSphere é uma aplicação web composta por frontend em React (Vite/TypeScript) e backend em Python (Flask/SQLite), integrada a serviços de inteligência e autenticação.

Este repositório contém a versão auditada e remediada da aplicação, contemplando correção de vulnerabilidades críticas (OWASP Top 10), hardening de segurança, esteira de observabilidade (SRE) com métricas Prometheus, logs estruturados em JSON, conteinerização com Docker e balanceamento de carga via Nginx.

---

## 🏛️ Arquitetura do Sistema

```
                         [ Usuário / Navegador ]
                                    │
                                    ▼ (Porta 80)
                ┌───────────────────────────────────────┐
                │        Nginx Reverse Proxy / LB       │
                │        (Gateway & Load Balancer)      │
                └───────┬───────────────────────┬───────┘
                        │                       │
         ┌──────────────┴──────────┐            ▼ (Proxy SPA)
         │  upstream backend_pool  │      ┌───────────────┐
         │     (Round-Robin)       │      │   Frontend    │
         └──┬───────────────────┬──┘      │ (React/Vite)  │
            ▼                   ▼         └───────────────┘
     ┌─────────────┐     ┌─────────────┐
     │  Backend 1  │     │  Backend 2  │
     │  (Gunicorn) │     │  (Gunicorn) │
     └──────┬──────┘     └──────┬──────┘
            │                   │
            └─────────┬─────────┘
                      ▼
             ┌─────────────────┐
             │ SQLite Database │
             │ (roster_reviews)│
             └─────────────────┘
                      │
         ┌────────────┴────────────┐
         │ Observabilidade (SRE)   │
         │ Prometheus (:9090)      │
         │ Grafana    (:3001)      │
         └─────────────────────────┘
```

---

## 🚀 Como Executar o Ambiente

### Pré-requisitos
- [Docker](https://docs.docker.com/get-docker/) e [Docker Compose](https://docs.docker.com/compose/) instalados;
- (Opcional para execução local direta) Python 3.11+ e Node.js 20+.

### 1. Inicialização Completa via Docker Compose (Recomendado)
Para subir todos os serviços (Nginx Gateway, 2 réplicas de Backend, Frontend, Prometheus e Grafana):

```bash
docker compose up --build -d
```

### 2. Endpoints e Portas de Acesso

| Serviço | URL | Descrição |
|---|---|---|
| **Aplicação Completa (Gateway)** | [http://localhost](http://localhost) | Entrada principal da aplicação via Nginx |
| **API Backend (Healthcheck)** | [http://localhost/health](http://localhost/health) | Probe de liveness e readiness |
| **Métricas Prometheus** | [http://localhost/metrics](http://localhost/metrics) | Métricas exportadas em formato OpenMetrics |
| **Prometheus Server** | [http://localhost:9090](http://localhost:9090) | Coletor de métricas e interface de consulta PromQL |
| **Dashboard Grafana** | [http://localhost:3001](http://localhost:3001) | Painéis visuais SRE (Login: `admin` / `admin`) |

---

## ⚖️ Demonstração de Balanceamento de Carga (SRE)

Para comprovar que o Nginx está distribuindo as requisições em regime *round-robin* entre as instâncias `backend-1` e `backend-2`, execute o script de auditoria incluído:

```bash
python3 scripts/demonstrate_load_balancing.py http://localhost/health 10
```

Saída de demonstração esperada:
```text
[*] Dispatching 10 requests to http://localhost/health...

Req #    | Status   | X-Served-By          | X-Upstream-Backend     | Latency (ms)
--------------------------------------------------------------------------------
1        | 200      | backend-1            | 172.20.0.3:5000        | 4.21        
2        | 200      | backend-2            | 172.20.0.4:5000        | 3.85        
3        | 200      | backend-1            | 172.20.0.3:5000        | 3.12        
4        | 200      | backend-2            | 172.20.0.4:5000        | 3.44        
...
--------------------------------------------------------------------------------
[+] Distribution Summary:
  - Instance 'backend-1': 5 requests (50.0%)
  - Instance 'backend-2': 5 requests (50.0%)
```

---

## 🧪 Testes Automatizados de Segurança e Regressão

Foram criados 12 testes unitários e de integração em `pytest` cobrindo as correções de autorização, injeção de SQL e os endpoints de observabilidade:

```bash
# Execução via ambiente virtual ou uvx
uvx --with flask --with flask-cors pytest backend/tests/ -v
```

---

## 🛡️ Ferramentas de Verificação Automatizada (SAST & SCA)

As análises estáticas e de dependências foram executadas e seus relatórios arquivados na pasta `audit_reports/`:

### 1. Bandit (SAST em Python)
```bash
uvx bandit -r backend/ -ll -ii
```

### 2. Semgrep (SAST Polyglot)
```bash
uvx semgrep scan --config=auto backend/
```

### 3. pip-audit (SCA de Dependências)
```bash
uvx pip-audit -r backend/requirements.txt
```

---

## 🔍 Como Reproduzir os Achados de Segurança

### 1. Injeção de SQL (VULN-01) — Neutralizada
- **Comportamento Anterior**: Concatenação direta de parâmetros em strings SQL (`f"SELECT * FROM courses WHERE semester = '{semester}'"`).
- **Como reproduzir**:
  ```bash
  # Requisição contendo payload de SQL Injection
  curl -i "http://localhost/courses/semester/'%20OR%201=1--"
  ```
- **Resultado Atual**: Retorna HTTP 404 (o payload é tratado estritamente como dado literal pela consulta parametrizada, sem executar lógica SQL arbitrária).

### 2. Vazamento de Token em Parâmetro GET (VULN-04) — Neutralizado
- **Comportamento Anterior**: Aceitava `GET /users/info?id_token=<JWT>`, registrando tokens em texto claro nos logs do servidor.
- **Como reproduzir**:
  ```bash
  curl -i "http://localhost/users/info?id_token=ey..."
  ```
- **Resultado Atual**: Retorna HTTP 401 Unauthorized (`"Insecure token transport: tokens must be transmitted in the Authorization HTTP header, not query parameters."`).

### 3. Desativação do Modo Debug e Stacktrace (VULN-03) — Neutralizado
- **Comportamento Anterior**: Servidor rodava com `debug=True`, expondo o depurador interativo do Werkzeug e stacktraces detalhados.
- **Resultado Atual**: `FLASK_DEBUG=0` por padrão; erros internos são capturados pelo handler global e retornam mensagem genérica padronizada sem vazar caminhos de arquivos.

---

## 📈 Métricas, SLIs e SLOs (SRE)

- **SLI 1 (Latência de Consulta)**: Percentual de requisições à API atendidas com latência inferior a 200ms.
  - **SLO 1**: 99.0% das requisições válidas atendidas em `< 200ms` em uma janela de 30 dias.
- **SLI 2 (Disponibilidade)**: Percentual de requisições com código de resposta diferente de `5xx`.
  - **SLO 2**: 99.5% de disponibilidade em uma janela de 30 dias.

O painel visual com monitoramento em tempo real dos SLIs está provisionado no **Grafana** em `http://localhost:3001`.
