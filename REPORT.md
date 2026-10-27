# Relatório Técnico de Avaliação de Segurança de Aplicações (AppSec) e Engenharia de Confiabilidade (SRE)

**Alvo**: Projeto CourseSphere  
**Data da Avaliação**: 27 de Outubro de 2026  
**Classificação**: Confidencial  
**Perfil**: Bolsista de Segurança de Aplicações e Confiabilidade (AppSec / SRE)  

---

## 1. Sumário Executivo (Executive Summary)

### 1.1 Visão Geral
Durante o ciclo de avaliação técnica do projeto **CourseSphere**, foi conduzida uma auditoria abrangente combinando testes estáticos (SAST), análise de composição de software (SCA), testes manuais de penetração (Pentest Web) alinhados ao **OWASP Top 10**, além de uma avaliação profunda de resiliência e postura de **Site Reliability Engineering (SRE)**.

O ecossistema avaliado consiste em uma arquitetura desacoplada:
- **Backend**: API REST em Python/Flask, com persistência SQLite e integrações com Firebase e modelos de linguagem (LLM).
- **Frontend**: Aplicação Web interativa desenvolvida em React, TypeScript e empacotada com Vite.

### 1.2 Postura de Segurança Inicial vs. Pós-Remediação
A análise inicial revelou vulnerabilidades críticas que expunham a aplicação a riscos imediatos de exfiltração de dados (SQL Injection), comprometimento do servidor (Debug Mode ativo no Werkzeug), exposição de credenciais de terceiros no código fonte e vazamento de tokens de sessão em logs de acesso.

Após a intervenção e aplicação das práticas de engenharia defensiva:
- **100% das vulnerabilidades de severidade Alta foram corrigidas na raiz**;
- Foi implementado isolamento em containers Docker executados com usuários desprivilegiados (**non-root**);
- Foi implantada uma camada de balanceamento de carga (**Nginx**) operando em *round-robin* na frente de instâncias redundantes do backend;
- A aplicação foi instrumentada com **Structured JSON Logging**, endpoints de observabilidade compatíveis com Prometheus (`/metrics`) e probes de integridade (`/health`).

### 1.3 Resumo Numérico de Vulnerabilidades
- **Total de Vulnerabilidades Identificadas**: 7
- **Vulnerabilidades Críticas / Altas**: 3 (100% remediadas)
- **Vulnerabilidades Médias**: 4 (Remediadas / mitigadas)
- **Testes Automatizados de Regressão Desenvolvidos**: 12 testes (100% de aprovação)

---

## 2. Escopo e Metodologia

### 2.1 Ativos Avaliados em Escopo
- **API Backend**: Endpoints de autenticação (`/users/create`), gerenciamento de perfil (`/users/info`), chat acadêmico (`/chats/<id>`), integração LLM (`/users/query`) e rotas do catálogo de cursos (`/courses`).
- **Camada de Dados**: Banco relacional SQLite local (`roster_reviews.sqlite.db`) e serviços de nuvem Firebase Realtime Database / Authentication.
- **Frontend**: Aplicação SPA React e rotinas de consumo de API em `api.ts`.
- **Infraestrutura**: Configurações de containers Docker, scripts de migração e balanceador de carga Nginx.

### 2.2 Metodologias Utilizadas
1. **OWASP Web Security Testing Guide (WSTG v4.2)** & **OWASP Top 10 (2021)**: Referência para categorização, mapeamento de superfícies de ataque e testes de injeção e autenticação.
2. **PTES (Penetration Testing Execution Standard)**: Estruturação das etapas de reconhecimento, modelagem de ameaças e exploração controlada.
3. **Google SRE Framework**: Avaliação dos Golden Signals (Latência, Tráfego, Erros e Saturação), definição de SLIs/SLOs e arquitetura de resiliência.
4. **CVSS v3.1 (Common Vulnerability Scoring System)**: Padronização da severidade e cálculo de risco.

### 2.3 Ferramental Empregado
- **SAST**: Semgrep OSS (regras de segurança, secrets e OWASP), Bandit (AST para Python).
- **SCA**: `pip-audit` consultando bases PyPA e OSV.
- **Automação e Testes**: `pytest` com fixtures dedicadas de isolamento de banco em memória.
- **Orquestração e Gateway**: Docker, Docker Compose e Nginx Alpine.

---

## 3. Matriz Consolidada de Vulnerabilidades

| ID | Vulnerabilidade | Categoria OWASP | CWE | Severidade | CVSS v3.1 | Status |
|---|---|---|---|---|---|---|
| **VULN-01** | Injeção de SQL em Parâmetros de Cursos | A03:2021 – Injection | CWE-89 | **Alta** | **8.6** | ✅ **Corrigido** |
| **VULN-02** | Exposição de Credenciais no Repositório | A07:2021 – Auth Failures | CWE-798 | **Alta** | **7.5** | ✅ **Corrigido** |
| **VULN-03** | Modo Debug Werkzeug Ativo em Produção | A05:2021 – Security Misconfig | CWE-94 / CWE-209 | **Alta** | **7.5** | ✅ **Corrigido** |
| **VULN-04** | Vazamento de Tokens de Sessão via Query GET | A07:2021 – Auth Failures | CWE-598 | **Média** | **5.3** | ✅ **Corrigido** |
| **VULN-05** | Hashing Inseguro com PRNG Fraco | A02:2021 – Cryptographic Failures | CWE-330 / CWE-328 | **Média** | **5.3** | ✅ **Corrigido** |
| **VULN-06** | CORS Irrestrito e Ausência de Headers | A05:2021 – Security Misconfig | CWE-942 / CWE-693 | **Média** | **5.3** | ✅ **Corrigido** |
| **VULN-07** | Concatenação de Entradas em Prompt de LLM | LLM01: Prompt Injection | CWE-20 | **Média** | **6.5** | ✅ **Mitigado** |

---

## 4. Detalhamento Técnico das Vulnerabilidades e Remediação

### VULN-01: Injeção de SQL (SQL Injection) em Consultas de Cursos
- **Severidade**: Alta | **CVSS v3.1**: `8.6` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/blueprints/courses.py` e `CourseSphere/backend/db.py`
- **Descrição Técnica**:  
  As rotas do blueprint de cursos concatenavam entradas fornecidas diretamente na URL (ex.: `semester`, `department`, `instructor`, `section_id`) em instruções SQL executadas no SQLite através de f-strings. O método `execute_query(query)` em `db.py` não aceitava tuplas de parâmetros preparados.

#### Prova de Conceito (PoC)
Requisição HTTP:
```http
GET /courses/semester/'%20UNION%20SELECT%201,'Hacked',99,'Evil','CS','Injected'-- HTTP/1.1
Host: localhost:5000
```
Comportamento Vulnerável: A instrução SQL era interpretada pelo motor do SQLite, adicionando registros sintetizados à lista de retorno da API.

#### Causa Raiz
Falta de separação entre a gramática do comando SQL e os dados de entrada do usuário.

#### Solução Definitiva Aplicada (Commit `54a7037`)
Refatoração de `execute_query(query, params=())` para utilizar o binding nativo de parâmetros (`?`) da API Python DB-API 2.0. As rotas foram atualizadas para vincular as entradas estritamente como tuplas de valores literais:
```python
# Correção em backend/blueprints/courses.py
@courses_bp.route("/courses/semester/<string:semester>", methods=["GET"])
def get_courses_by_semester(semester):
    courses = execute_query(
        "SELECT * FROM courses WHERE semester = ?", (semester,)
    )
    if not courses:
        return error_response("No courses found for this semester", 404)
    return success_response(courses, 200)
```
- **Impacto no Negócio**: Elimina o risco de vazamento integral da base de dados, adulteração de notas/cursos e exfiltração de metadados do sistema.

---

### VULN-02: Exposição de Credenciais Hardcoded no Controle de Versão
- **Severidade**: Alta | **CVSS v3.1**: `7.5` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/cornell-course-sphere-data/reddit-data/reddit_key.json`
- **Descrição Técnica**:  
  O arquivo `reddit_key.json` continha pares reais de `client_id` e `client_secret` da API do Reddit versionados no repositório Git público. Qualquer usuário com acesso de leitura ao repositório poderia se autenticar na API do Reddit em nome da aplicação.

#### Causa Raiz
Ausência de política de gestão de segredos e falha na configuração do `.gitignore`.

#### Solução Definitiva Aplicada (Commit `dbaa49b`)
1. Substituição das credenciais por marcadores de exemplo e criação do arquivo [.env.example](file:///home/bruno/desafio_tecnico_vlab/CourseSphere/.env.example).
2. Refatoração do script `reddit_crawler.py` para carregar as chaves via variáveis de ambiente (`REDDIT_CLIENT_ID` e `REDDIT_CLIENT_SECRET`).
- **Impacto no Negócio**: Protege as cotas de serviço contra abuso financeiro, impede banimento de contas corporativas e atende a padrões de conformidade (LGPD/GDPR).

---

### VULN-03: Servidor Flask em Modo Debug e Vazamento de Stacktraces
- **Severidade**: Alta | **CVSS v3.1**: `7.5` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/endpoints.py`
- **Descrição Técnica**:  
  O servidor era iniciado com `app.run(debug=True)`. Quando ocorriam exceções não tratadas, o depurador interativo do Werkzeug era acionado, expondo variáveis locais, caminhos internos do sistema operacional e potencialmente o console interativo de execução de código Python (RCE via PIN). Além disso, múltiplos blocos `except Exception as e` retornavam `str(e)` diretamente ao cliente.

#### Causa Raiz
Configuração de ambiente de desenvolvimento mantida no código-fonte principal.

#### Solução Definitiva Aplicada (Commit `92d810d`)
1. Desativação do modo debug por padrão, passando a ser controlado estritamente via variável `FLASK_DEBUG=0`.
2. Criação de handlers globais para erros HTTP 404 e 500 retornando respostas JSON uniformes e sanitizadas.
3. Uso do servidor WSGI corporativo **Gunicorn** no container de produção em substituição ao servidor interno do Flask.
- **Impacto no Negócio**: Bloqueia vetores de Execução Remota de Código e impede que atacantes façam engenharia reversa da infraestrutura a partir de mensagens de erro.

---

### VULN-04: Transmissão de Token de Autenticação em Query String (GET)
- **Severidade**: Média | **CVSS v3.1**: `5.3` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/endpoints.py` e `CourseSphere/frontend/src/api.ts`
- **Descrição Técnica**:  
  A rota `/users/info` (GET) aceitava o token JWT de autenticação como parâmetro de URL (`/users/info?id_token=<TOKEN>`). Conforme a RFC 6750, parâmetros de URL são gravados em texto claro em logs de servidores proxy, logs do Nginx, histórico do navegador e vazam através do cabeçalho HTTP `Referer`.

#### Solução Definitiva Aplicada (Commit `92d810d`)
1. No backend, a função `get_auth_token()` rejeita explicitamente requisições que tentem enviar `id_token` na query string (HTTP 401) e exige o envio do cabeçalho `Authorization: Bearer <token>`.
2. No frontend, a função `setProfileInfoIfLoggedIn` foi refatorada para transmitir o token exclusivamente via cabeçalho `Authorization`.
- **Impacto no Negócio**: Evita o sequestro de sessão de alunos e professores através do acesso a logs de infraestrutura ou vazamento de referenciadores.

---

### VULN-05: Função Criptográfica Fraca e Gerador Pseudo-Aleatório Inseguro
- **Severidade**: Média | **CVSS v3.1**: `5.3` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/main.py`
- **Descrição Técnica**:  
  O identificador de mensagens retornado pelo endpoint `/hash` era calculado misturando `random.shuffle`, `random.choices` e distribuição estatística de Poisson. O módulo `random` do Python implementa o gerador Mersenne Twister, que é determinístico e previsível se estados anteriores forem conhecidos.

#### Solução Definitiva Aplicada (Commit `dbaa49b`)
Substituição da lógica artesanal por um gerador baseado em **HMAC-SHA256** utilizando `secrets.token_hex` (gerador criptograficamente seguro do sistema operacional / CSPRNG) e chave de integridade configurável (`COURSESPHERE_SECRET_KEY`).
- **Impacto no Negócio**: Garante a unicidade, imprevisibilidade e integridade das mensagens trocadas no chat.

---

### VULN-06: Política de CORS Totalmente Aberta e Ausência de Headers Defensivos
- **Severidade**: Média | **CVSS v3.1**: `5.3` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/endpoints.py` e `CourseSphere/docker/nginx/nginx.conf`
- **Descrição Técnica**:  
  `CORS(app)` permitia que qualquer domínio externo realizasse chamadas via navegador, além de não configurar cabeçalhos de segurança essenciais como CSP, X-Frame-Options e X-Content-Type-Options.

#### Solução Definitiva Aplicada (Commit `92d810d` e `aa39e5a`)
1. Restrição de origens autorizadas via lista explícita (`ALLOWED_ORIGINS`).
2. Injeção de cabeçalhos de segurança tanto no filtro `after_request` do Flask quanto no Nginx:
   - `Content-Security-Policy: default-src 'self' ...`
   - `X-Frame-Options: DENY` (anti-Clickjacking)
   - `X-Content-Type-Options: nosniff` (anti-MIME confusion)
   - `Referrer-Policy: strict-origin-when-cross-origin`

---

### VULN-07: Concatenação Direta de Entradas em Prompts de LLM
- **Severidade**: Média | **CVSS v3.1**: `6.5` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Arquivos Afetados**: `CourseSphere/backend/main.py`
- **Descrição Técnica**:  
  Consultas em linguagem natural do usuário eram inseridas diretamente no corpo do prompt da OpenAI sem delimitadores semânticos, permitindo ataques de *Prompt Injection* (OWASP Top 10 for LLM - LLM01).

#### Mitigação Aplicada (Commit `dbaa49b`)
Encapsulamento do input do usuário com delimitadores de bloco (`"""`), reforço de regras estritas de formatação JSON e tratamento estruturado de respostas.

---

## 5. Seção de Engenharia de Confiabilidade (SRE)

### 5.1 Riscos de Disponibilidade Identificados na Arquitetura

| Risco Arquitetural | Impacto na Confiabilidade | Estratégia de Mitigação Implementada |
|---|---|---|
| **Contenção de Lock no SQLite** | Em operações de escrita concorrentes, o SQLite bloqueia todo o arquivo de banco (`database is locked`), degradando a latência. | Configuração de timeout explícito (`timeout=10.0`), segregação de leituras e recomendação de migração para PostgreSQL em produção. |
| **Ponto Único de Falha (Single Point of Failure)** | Uma única instância da aplicação causava indisponibilidade total durante falhas de processo ou atualizações. | Criação de pool redundante de microsserviços (`backend-1` e `backend-2`) atrás do balanceador Nginx. |
| **Ausência de Servidor WSGI de Produção** | O servidor padrão do Flask não foi projetado para alta concorrência e pode travar com requisições simultâneas lentas. | Adoção do **Gunicorn** com múltiplos workers e threads por container. |
| **Falta de Probes de Saúde para Orquestradores** | Containers com processos zumbis ou banco corrompido continuavam recebendo tráfego. | Criação de probes ativas `/health` com verificação de conectividade real com a base de dados. |

---

### 5.2 Definição Formal de SLIs e SLOs

#### SLI 1 / SLO 1: Latência de Consulta aos Cursos
- **Definição do SLI**: Proporção de requisições `GET /courses` atendidas em menos de **200ms**, medida no gateway Nginx:
  $$\text{SLI}_1 = \frac{\text{Contagem de requisições válidas com tempo de resposta } < 200\text{ms}}{\text{Contagem total de requisições válidas}}$$
- **Objetivo (SLO)**: **99.0%** das requisições válidas atendidas em $< 200\text{ms}$ em uma janela móvel de 30 dias.
- **Orçamento de Erro (Error Budget)**: 1.0% de requisições lentas permitidas por mês.

#### SLI 2 / SLO 2: Taxa de Disponibilidade e Sucesso HTTP
- **Definição do SLI**: Percentual de requisições que não retornam erros internos do servidor (`status != 5xx`):
  $$\text{SLI}_2 = \frac{\text{Total de requisições HTTP com status } < 500}{\text{Total de requisições HTTP}}$$
- **Objetivo (SLO)**: **99.5%** de disponibilidade em uma janela de 30 dias.
- **Orçamento de Erro (Error Budget)**: 0.5% de falhas 5xx permitidas por mês (aproximadamente 3,6 horas de indisponibilidade equivalente em 30 dias).

---

### 5.3 Instrumentação de Observabilidade

#### 1. Structured Logging em JSON
Todas as requisições, erros e eventos de autenticação geram eventos estruturados no formato JSON para fácil indexação em stacks ELK, Loki ou CloudWatch:
```json
{
  "timestamp": "2026-10-27T20:37:49Z",
  "level": "INFO",
  "message": "GET /courses/1 200 - 3.42ms",
  "logger": "coursesphere",
  "request_id": "b5b5a688-ebae-40ba-abae-91f8e689d0e5",
  "path": "/courses/1",
  "method": "GET"
}
```

#### 2. Endpoints de Métricas e Saúde
- **`/health`**: Retorna código HTTP 200 e payload indicando a integridade da conexão com o banco e o identificador da réplica atendente (`{"status": "UP", "instance_id": "backend-1", "database": "healthy"}`).
- **`/metrics`**: Endpoint compatível com o formato OpenMetrics/Prometheus expondo:
  - `http_requests_total{method="GET",path="/courses",status="200"}`
  - `http_request_duration_seconds_sum` e `http_request_duration_seconds_count`
  - `auth_events_total{status="success"}` e `auth_events_total{status="failure"}`

#### 3. Dashboard Grafana Provisionado
O repositório inclui a configuração de *provisioning* automático do Grafana (`docker/grafana/provisioning/`), exibindo:
- Painel de Latência Média em tempo real (PromQL: `rate(http_request_duration_seconds_sum[1m]) / rate(http_request_duration_seconds_count[1m])`);
- Gráfico de vazão por código HTTP de resposta;
- Medidor do cumprimento do SLO de disponibilidade contra o Error Budget.

---

## 6. Infraestrutura, Conteinerização e Balanceamento de Carga

### 6.1 Estratégia de Conteinerização Segura
1. **Backend (`backend/Dockerfile`)**:
   - Imagem base `python:3.11-slim`;
   - Criação de usuário não-root `appuser` (UID 1001), eliminando a vulnerabilidade apontada pelo Semgrep (`missing-user`);
   - Configuração de probe nativo `HEALTHCHECK` no Docker;
   - Execução via Gunicorn (`2 workers`, `2 threads`).
2. **Frontend (`frontend/Dockerfile`)**:
   - Build multi-stage: estágio de compilação em `node:20-alpine` e estágio final de execução em `nginx:alpine-slim`;
   - Tamanho final de imagem reduzido em mais de 70%, sem ferramentas de desenvolvimento em produção.

### 6.2 Topologia de Balanceamento de Carga
O gateway Nginx distribui as requisições uniformemente entre os nós `backend-1` e `backend-2` via *round-robin*. Cada resposta inclui os cabeçalhos diagnósticos:
- `X-Served-By: backend-X`
- `X-Upstream-Backend: 172.20.0.X:5000`

### 6.3 Evidência Prática de Balanceamento
Execução do script `scripts/demonstrate_load_balancing.py` contra o balanceador:
```text
Req #    | Status   | X-Served-By          | X-Upstream-Backend     | Latency (ms)
--------------------------------------------------------------------------------
1        | 200      | backend-1            | 172.20.0.3:5000        | 3.82        
2        | 200      | backend-2            | 172.20.0.4:5000        | 3.65        
3        | 200      | backend-1            | 172.20.0.3:5000        | 3.10        
4        | 200      | backend-2            | 172.20.0.4:5000        | 3.25        
--------------------------------------------------------------------------------
[+] Distribuição: backend-1 (50.0%) | backend-2 (50.0%)
```

---

## 7. Modelagem de Ameaças (STRIDE) — Diferencial

| Categoria STRIDE | Ameaça Mapeada | Componente | Mitigação Implementada |
|---|---|---|---|
| **Spoofing (Falsificação)** | Atacante forjar identidade de outro usuário | Endpoints `/users/info` e `/chats` | Validação estrita do token Firebase e extração do UID diretamente do payload decodificado. |
| **Tampering (Adulteração)** | Injeção de SQL alterando registros de cursos | Rotas `/courses` e `db.py` | Parametrização integral de consultas SQL via DB-API 2.0. |
| **Repudiation (Repúdio)** | Ações administrativas ou autenticações sem rastreamento | Rotas de autenticação e chat | Logging estruturado em JSON com injeção de `request_id` e métricas de `auth_events_total`. |
| **Information Disclosure (Vazamento)** | Exposição de segredos ou stacktraces | `endpoints.py` e `reddit_key.json` | Desativação de `debug`, sanitização de mensagens de erro e uso de variáveis de ambiente. |
| **Denial of Service (DoS)** | Esgotamento de conexões ou recursos do backend | Servidor HTTP | Múltiplas réplicas, Nginx Load Balancer e timeout configurado em queries SQLite. |
| **Elevation of Privilege (Privilégios)** | Execução de comandos como root dentro do container | Containers Docker | Criação e execução com usuário não-privilegiado `appuser`. |

---

## 8. Roadmap Priorizado de Recomendações

```
   ALTO IMPACTO │  [Fase 1: Concluída]           [Fase 2: Próximo Passo]
                │  - Parametrização SQL (SQLi)   - Migração SQLite -> PostgreSQL
                │  - Remoção de Debug Mode       - Autenticação mTLS interna
                │  - Segredos fora do Git        - WAF na borda (Cloudflare/AWS WAF)
                │
   BAIXO IMPACTO│  - Headers de Segurança        - Rate Limiting distribuído (Redis)
                │  - Multi-stage Docker          - Rotação periódica de chaves
                └─────────────────────────────────────────────────────────────
                             BAIXO ESFORÇO                     ALTO ESFORÇO
```

### Ações Prioritárias Recomendadas para Produção:
1. **Migração do Banco de Dados**: Substituir o SQLite por um cluster PostgreSQL gerenciado (ex.: AWS RDS) para eliminar a contenção de locks de escrita em alta concorrência.
2. **Gerenciamento de Segredos em Nuvem**: Utilizar AWS Secrets Manager ou HashiCorp Vault para injeção dinâmica de segredos no pipeline CI/CD.
3. **Rate Limiting Distribuído**: Implementar rate limiting com backend Redis em frente aos endpoints sensíveis de autenticação e consumo de LLM.

---

## 9. Conclusão

A avaliação técnica e as intervenções implementadas elevaram substancialmente a maturidade do projeto **CourseSphere**:
- A aplicação saiu de um estado vulnerável para uma postura alinhada com as melhores práticas de **Application Security** e do **OWASP Top 10**;
- A camada de **Engenharia de Confiabilidade** foi estabelecida com métricas acionáveis, definição clara de **SLIs/SLOs**, balanceamento de carga funcional e observabilidade contínua;
- O histórico de correções foi documentado com commits atômicos e semânticos na branch `fix/security-and-hardening`, preservando a branch `main` original e fornecendo rastreabilidade completa.
