# 🎓 CourseSphere — Plataforma de Recomendação e Gestão de Cursos
> **Projeto de Avaliação Técnica — Bolsista de Segurança de Aplicações e Confiabilidade (AppSec / SRE)**

CourseSphere é uma aplicação web composta por frontend em React (Vite/TypeScript) e backend em Python (Flask/SQLite), integrada a serviços de inteligência (OpenAI) e autenticação (Firebase / HMAC Session Tokens).

Este repositório contém a versão auditada, remediada e instrumentada da aplicação na branch `fix/security-and-hardening`, contemplando:
- **AppSec (OWASP Top 10:2021)**: Remediação completa de 9 vulnerabilidades (`PT-001` a `PT-009`), incluindo Injeção de SQL, Credenciais Hardcoded, RCE/Debug Werkzeug, Quebra de Controle de Acesso (BOLA/IDOR e endpoints não autenticados), Tokens em Query String, Path Traversal, Criptografia Fraca (`scrypt` + HMAC-SHA256), Prompt Injection, CVEs de dependências NPM e ausência de Headers HTTP / Rate Limiting.
- **SRE & Resiliência**: Instrumentação OpenMetrics/Prometheus (`/metrics` com histogramas de latência), Logs Estruturados em JSON com `request_id` e `actor_uid`, **Circuit Breaker** (`CLOSED`/`OPEN`/`HALF_OPEN`) + **Retry com Backoff Exponencial e Jitter**, Healthcheck ativo (`/health`), **Docker Compose** com Nginx Load Balancer (2 réplicas Gunicorn não-root) e **Manifestos Kubernetes (`k8s/manifests.yaml`)** com HPA, NetworkPolicy e Probes.

---

## 🏛️ Arquitetura do Sistema

```
                         [ Usuário / Navegador ]
                                    │
                                    ▼ (Porta 80)
                ┌───────────────────────────────────────┐
                │        Nginx Reverse Proxy / LB       │
                │   (Gateway, Rate Limit & Headers)     │
                └───────┬───────────────────────┬───────┘
                        │                       │
         ┌──────────────┴──────────┐            ▼ (Proxy SPA)
         │  upstream backend_pool  │      ┌───────────────┐
         │     (Round-Robin)       │      │   Frontend    │
         └──┬───────────────────┬──┘      │ (React/Vite)  │
            ▼                   ▼         │  (Non-Root)   │
     ┌─────────────┐     ┌─────────────┐  └───────────────┘
     │  Backend 1  │     │  Backend 2  │
     │  (Gunicorn) │     │  (Gunicorn) │
     │ +CircuitBrk │     │ +CircuitBrk │
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
- (Opcional para execução local de testes e SAST) Python 3.11+ / `uv`.

### 1. Inicialização Completa via Docker Compose (Recomendado)
Para subir todos os serviços (Nginx Gateway, 2 réplicas de Backend Gunicorn, Frontend React não-root, Prometheus e Grafana):

```bash
docker compose up --build -d
```

### 2. Deploy Opcional em Kubernetes (Diferencial Técnico)
O repositório inclui manifestos Kubernetes prontos para produção em [`k8s/manifests.yaml`](k8s/manifests.yaml) contendo `Deployment` (3 réplicas, `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `livenessProbe` e `readinessProbe`), `Service`, `HorizontalPodAutoscaler` e `NetworkPolicy`:

```bash
kubectl apply -f k8s/manifests.yaml
```

### 3. Endpoints e Portas de Acesso

| Serviço | URL / Rota | Descrição |
|---|---|---|
| **Aplicação Completa (Gateway)** | `http://localhost` | Entrada principal da aplicação via Nginx |
| **API Backend (Healthcheck)** | `GET http://localhost/health` | Probe ativo de liveness/readiness (valida DB + Circuit Breakers) |
| **Métricas Prometheus** | `GET http://localhost/metrics` | Métricas exportadas em formato OpenMetrics (Histogramas, Contadores e Gauges) |
| **Autenticação com Rate Limit** | `POST http://localhost/users/login` | Login com `scrypt`, emissão de token HMAC com expiração e bloqueio após 5 falhas (`429`) |
| **CRUD de Cursos (Autorizado)** | `POST / PUT / DELETE /courses` | Criação, edição e remoção de cursos restrita ao `creator_uid` (`403 Forbidden` para terceiros) |
| **Prometheus Server** | `http://localhost:9090` | Coletor de métricas e interface de consulta PromQL |
| **Dashboard Grafana** | `http://localhost:3001` | Painéis visuais SRE provisionados automaticamente (`admin` / `admin`) |

---

## ⚖️ Demonstração de Balanceamento de Carga (SRE)

Para comprovar que o Nginx está distribuindo as requisições em regime *round-robin* entre as instâncias `backend-1` e `backend-2`, execute o script de auditoria incluído:

```bash
python3 scripts/demonstrate_load_balancing.py http://localhost/health 10
```

Saída esperada:
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

## 🧪 Suíte de Testes Automatizados de Segurança e Confiabilidade (29 Testes)

Foram implementados **29 testes automatizados** em `pytest` (`backend/tests/test_courses_security.py` e `backend/tests/test_endpoints_security.py`) cobrindo:
- Neutralização de SQL Injection em todas as rotas de cursos e migração de dados;
- Controle de acesso por propriedade de recurso (**BOLA/IDOR**): usuário autenticado tentando editar (`PUT /courses/<id>`) ou excluir (`DELETE /courses/<id>`) curso de outro criador recebe **`HTTP 403 Forbidden`**;
- Prevenção de **Account Takeover (`CWE-620`)**: recadastro de e-mail existente em `POST /users/create` é bloqueado com **`HTTP 409 Conflict`** sem sobrescrever a senha original;
- Rejeição estrita de tokens não assinados (`test-token-*` -> `HTTP 401`), de tokens em query string (`?id_token=` -> `HTTP 401`) ou body JSON (`id_token` -> `HTTP 401`), exigindo `Authorization: Bearer <csjwt>`;
- Sanitização de payloads XSS (`<script>`) na criação e edição de cursos e mensagens de chat;
- **Rate Limiting e Brute-Force Lockout** por IP e por conta em `POST /users/login` (`HTTP 429 Too Many Requests` + `Retry-After` após 5 falhas) e validação CIDR RFC 1918 contra spoofing de `X-Forwarded-For`;
- Expiração criptográfica de tokens HMAC, hashing de senhas com `scrypt` e fail-closed em produção sem `COURSESPHERE_SECRET_KEY`;
- Bloqueio de **Path Traversal** (`../`) e proteção **CSRF / Origin / Content-Type (`415`)**;
- Transições de estado do **Circuit Breaker** (`CLOSED -> OPEN -> HALF_OPEN -> CLOSED`), consistência multi-réplica e controle de cardinalidade em `/metrics`.

```bash
export PATH="$HOME/.local/bin:$PATH"
uvx --with flask --with flask-cors pytest backend/tests/ -v
```

---

## 🛡️ Ferramentas de Verificação Automatizada (SAST & SCA)

### 1. Bandit (SAST em Python — 0 Issues)
```bash
uvx bandit -r backend/ --exclude backend/tests -ll -ii
```

### 2. Semgrep (SAST Polyglot — 0 Findings)
```bash
uvx semgrep scan --config=auto
```

### 3. pip-audit (SCA de Dependências Python)
```bash
uvx pip-audit -r backend/requirements.txt
```

---

## 🔍 Como Reproduzir as Correções dos Achados (`PT-001` a `PT-009`)

1. **Injeção de SQL (`PT-001`)**:
   ```bash
   curl -i "http://localhost/courses/semester/'%20OR%201=1--"
   # Retorna HTTP 404 (payload tratado como literal via prepared statements `?`)
   ```
2. **Controle de Acesso / BOLA em Cursos (`PT-005`)**:
   - Criar curso como `user_alice` (`POST /courses`) e tentar atualizar (`PUT /courses/<id>`) com token de `user_bob`:
   - Retorna **`HTTP 403 Forbidden`** (`"Forbidden: only the course creator can modify this course."`).
3. **Bloqueio de Força Bruta / Rate Limiting (`PT-009`)**:
   - Enviar 5 requisições `POST /users/login` com senha incorreta seguidas de uma 6ª tentativa:
   - Retorna **`HTTP 429 Too Many Requests`** com cabeçalho `Retry-After`.
4. **Rejeição de Token em Query Parameter (`PT-006`)**:
   ```bash
   curl -i "http://localhost/users/info?id_token=ey..."
   # Retorna HTTP 401 Unauthorized
   ```

---

## 📈 Métricas, SLIs e SLOs (SRE)

- **SLI 1 (Latência de Consulta — Histograma Prometheus)**: Proporção de requisições HTTP atendidas com latência inferior a `200ms` (`http_request_duration_seconds_bucket{le="0.2"}`).
  - **SLO 1**: **99.0%** das requisições válidas atendidas em `< 200ms` em janela móvel de 30 dias.
- **SLI 2 (Disponibilidade)**: Proporção de requisições HTTP com status diferente de `5xx`.
  - **SLO 2**: **99.5%** de disponibilidade em janela móvel de 30 dias.

Consulte o relatório técnico completo em [`REPORT.md`](REPORT.md).
