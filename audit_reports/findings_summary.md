# Relatório Preliminar de Análise de Vulnerabilidades (Fase 1 e Fase 2)
**Projeto Alvo**: CourseSphere  
**Data**: 27 de Outubro de 2026  
**Auditor**: Antigravity (AppSec & SRE Specialist)  

---

## 1. Ferramentas Automatizadas Executadas (SAST / SCA)
Como parte do Requisito 7 do edital, foram executadas análises automatizadas cujos relatórios completos foram gerados na pasta `audit_reports/`:

1. **Bandit (SAST - Python)**:
   - **Arquivo**: `audit_reports/bandit_report.txt`
   - **Total de Alertas**: 20 questões detectadas (1 High, 15 Medium, 4 Low).
   - **Destaques**: Detecção de `debug=True` no Flask (`B201`), concatenações inseguras de SQL em f-strings (`B608`), e uso de geradores pseudo-aleatórios fracos para criptografia (`B311`).
2. **Semgrep (SAST - Polyglot)**:
   - **Arquivo**: `audit_reports/semgrep_report.json`
   - **Total de Alertas**: 24 achados bloqueantes.
   - **Destaques**: SQL Injection com entrada contaminada (`tainted-sql-string`), Dockerfile sem especificação de usuário não-root (`missing-user`), e requisições HTTP inseguras não criptografadas.
3. **pip-audit (SCA - Dependências Backend)**:
   - **Arquivo**: `audit_reports/pip_audit_report.json`
   - **Resultado**: Dependências base mapeadas e verificadas contra a base PyPA/OSV.

---

## 2. Matriz Consolidada de Vulnerabilidades Identificadas

| ID | Vulnerabilidade | Categoria OWASP | CWE | Severidade | CVSS v3.1 | Status |
|---|---|---|---|---|---|---|
| **VULN-01** | SQL Injection em Rotas de Cursos | A03:2021 – Injection | CWE-89 | **Alta** | 8.6 | ⚠️ Confirmada |
| **VULN-02** | Credenciais Hardcoded no Controle de Versão | A07:2021 – Auth Failures | CWE-798 | **Alta** | 7.5 | ⚠️ Confirmada |
| **VULN-03** | Modo Debug Ativo com Exposição de Stacktrace | A05:2021 – Security Misconfiguration | CWE-94 / CWE-209 | **Alta** | 7.5 | ⚠️ Confirmada |
| **VULN-04** | Vazamento de Tokens JWT via URL Query (GET) | A07:2021 – Auth Failures | CWE-598 | **Média** | 5.3 | ⚠️ Confirmada |
| **VULN-05** | Hashing Customizado Inseguro e PRNG Fraco | A02:2021 – Cryptographic Failures | CWE-330 / CWE-328 | **Média** | 5.3 | ⚠️ Confirmada |
| **VULN-06** | CORS Irrestrito e Ausência de Headers de Proteção | A05:2021 – Security Misconfiguration | CWE-942 / CWE-693 | **Média** | 5.3 | ⚠️ Confirmada |
| **VULN-07** | Injeção de Prompt / Ausência de Sanitização LLM | LLM01: Prompt Injection | CWE-20 | **Média** | 6.5 | ⚠️ Confirmada |

---

## 3. Detalhamento dos Achados

### VULN-01: Injeção de SQL (SQL Injection) em Consultas de Cursos
- **Localização**: `CourseSphere/backend/blueprints/courses.py` (L30, L47, L64, L80, L96, L112) e `CourseSphere/backend/db.py` (L6-L12).
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**8.6** - Alta)
- **Descrição Técnica**: Parâmetros recebidos via rota (como `semester`, `department`, `instructor`) são concatenados diretamente via f-strings em instruções SQL executadas por `cursor.execute(query)` sem uso de parâmetros seguros.
- **Passo a Passo de Reprodução**:
  ```bash
  # Injeção via parâmetro de busca
  curl -s "http://127.0.0.1:5000/courses/'%20UNION%20SELECT%201,2,sqlite_version(),4,5--"
  ```
- **Impacto de Negócio**: Permite acesso não autorizado ao banco de dados SQLite, extração de dados sensíveis de cursos e potenciais alterações estruturais.

### VULN-02: Exposição de Credenciais no Repositório (Hardcoded Secrets)
- **Localização**: `CourseSphere/backend/cornell-course-sphere-data/reddit-data/reddit_key.json` e `CourseSphere/frontend/src/firebaseConfig.ts`.
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**7.5** - Alta)
- **Descrição Técnica**: Chaves de API (`client_id` e `client_secret` da API do Reddit, além de configurações do Firebase) estão salvas em texto plano e commitadas no Git.
- **Impacto de Negócio**: Acesso indevido a APIs de terceiros, sequestro de identidade de aplicativo e consumo não autorizado de cotas.

### VULN-03: Depurador Werkzeug Ativo em Produção (Debug=True)
- **Localização**: `CourseSphere/backend/endpoints.py` (L108).
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**7.5** - Alta)
- **Descrição Técnica**: O servidor Flask é iniciado com `debug=True`. Qualquer exceção não capturada ativa o console interativo do Werkzeug e exibe o stacktrace completo com arquivos, variáveis e caminhos locais.
- **Impacto de Negócio**: Divulgação de informações sobre a arquitetura do servidor e risco crítico de Execução Remota de Código (RCE).

### VULN-04: Transmissão de Token de Autenticação em Query String GET
- **Localização**: `CourseSphere/backend/endpoints.py` (L56-L63) e `CourseSphere/frontend/src/api.ts` (L91).
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (**5.3** - Média)
- **Descrição Técnica**: O endpoint `/users/info` recebe o `id_token` do usuário no formato `?id_token=<JWT>` via método GET.
- **Impacto de Negócio**: Tokens são gravados em logs de proxy, histórico de navegação e cabeçalhos `Referer`, possibilitando o sequestro de sessão do usuário.

### VULN-05: Função Criptográfica Fraca e Gerador Pseudo-Aleatório Não Criptográfico
- **Localização**: `CourseSphere/backend/main.py` (L14-L19) e `CourseSphere/backend/endpoints.py` (L74-L83).
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (**5.3** - Média)
- **Descrição Técnica**: Uso da biblioteca padrão `random` (Mersenne Twister) em vez do módulo `secrets` ou hashes padrão (SHA-256 padronizado, HMAC ou UUIDv4). A função mistura Poisson e shuffle aleatório, tornando o identificador previsível e instável.
- **Impacto de Negócio**: Colisão e previsibilidade de IDs de mensagens em sessões de chat.

### VULN-06: Configuração de CORS Irrestrita e Ausência de Headers de Segurança
- **Localização**: `CourseSphere/backend/endpoints.py` (L8).
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (**5.3** - Média)
- **Descrição Técnica**: Uso de `CORS(app)` sem definição de domínios confiáveis, associado à ausência de CSP, HSTS e X-Frame-Options.
- **Impacto de Negócio**: Exposição da API a chamadas de navegadores de origens não autorizadas e vulnerabilidade a ataques de Clickjacking.

### VULN-07: Injeção de Prompt em Consultas de LLM
- **Localização**: `CourseSphere/backend/main.py` (L26-L50) e `CourseSphere/backend/endpoints.py` (L65-L72).
- **CVSS v3.1**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (**6.5** - Média)
- **Descrição Técnica**: Entrada de texto do usuário é interpolada diretamente no template do prompt do modelo OpenAI sem sanitização de delimitadores ou escaping de instruções.
- **Impacto de Negócio**: Modificação indevida das instruções do assistente e manipulação de respostas retornadas aos alunos.
