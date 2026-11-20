# Template de remediação — Agentic IAM Accelerator

Origem: auditoria em `security_audit_report.md` (2 CRITICAL, 9 HIGH, 15 MEDIUM, 10 LOW).
Repositório: `agentic_iam`

## Como usar

1. Execute uma tarefa por sessão do agente, na ordem da tabela "Ordem e dependências".
2. Use o prompt modelo abaixo trocando o id da tarefa.
3. Revise o diff e os critérios de aceite antes de passar para a próxima.

Prompt modelo:

```text
Leia remediation_tasks_template.md. Implemente somente a tarefa T0X.
Siga a seção "Regras globais". Ao terminar, rode os testes e reporte cada
critério de aceite individualmente, indicando o que não pôde ser verificado.
Não inicie outra tarefa.
```

## Regras globais (valem para todas as tarefas)

- Uma tarefa por branch e por PR. Não misture tarefas.
- Localize o código pelo nome da função. Os números de linha são dicas da árvore
  auditada e mudam após cada tarefa.
- Não altere comportamento fora do escopo da tarefa. Preserve comentários e
  docstrings não relacionados.
- Testes sem rede e sem credenciais reais. Não execute scripts de deploy, `gcloud`
  nem chamadas a GCP ou Vertex AI.
- Não toque em `exports/` nem em `.env`, exceto na tarefa T16.
- Toda tarefa termina com `pytest -q` verde.
- Se um critério de aceite não puder ser cumprido, pare e relate. Não contorne
  enfraquecendo o teste.
- Itens marcados "Confirmar antes" dependem de comportamento de biblioteca ou de
  GCP que a auditoria não verificou. Verifique e relate o que encontrou.

## Decisões assumidas por padrão

Troque antes de executar a tarefa correspondente, se discordar.

| Decisão | Padrão assumido | Afeta |
|---|---|---|
| Policy Simulator | Remover a afirmação de verificação; não implementar replay agora | T03 |
| Terraform | Template determinístico a partir de plano estruturado | T06 |
| Acesso aberto a qualquer conta Google | Manter possível, mas só com opt-in explícito no deploy | T15 |
| Sessões | Instância única com afinidade; sem armazenamento externo | T09 |
| `exports/` no git | Só `git rm --cached`; não reescrever histórico | T16 |

## Ordem e dependências

| Ordem | Tarefa | Prioridade | Cobre | Depende de |
|---|---|---|---|---|
| 1 | T00 Infra de testes | P0 | M15 | — |
| 2 | T01 Kit de onboarding | P0 | C1 | T00 |
| 3 | T02 Deliverables por escopo | P0 | C2 | T00 |
| 4 | T03 Afirmações não verificadas | P0 | H3 | T00 |
| 5 | T04 Autenticação | P0 | H1, H2, M1 | T00 |
| 6 | T13 Validação de escopo e caches | P1 | M3, M4 | T00 |
| 7 | T05 Coleta completa e cobertura | P1 | H4, M6 | T13 |
| 8 | T07 Grounding da saída da LLM | P1 | H6 | T05 |
| 9 | T06 Terraform determinístico | P1 | H5 | T07 |
| 10 | T08 Execução e timeouts | P1 | H7 | T05 |
| 11 | T09 Estado e wipe | P1 | H8, M2 | T04 |
| 12 | T10 Relatórios robustos | P1 | H9, M14 | T02, T03 |
| 13 | T11 Correções do score | P2 | M5, M6 | T05 |
| 14 | T12 Classificação e grafo | P2 | M7, M8, M9 | T05 |
| 15 | T14 Superfície web | P2 | M12, L5, L6 | T04 |
| 16 | T15 Scripts de deploy | P2 | M11 | T09 |
| 17 | T16 Higiene do repositório | P2 | M13, M15 | — |
| 18 | T17 Limpeza LOW | P3 | L1–L4, L7–L10 | todas |

---

## T00 — Infra de testes

- **Prioridade:** P0. **Cobre:** M15 (parte).
- **Problema:** não há nenhum teste; todas as tarefas seguintes exigem testes offline.
- **Mudanças exigidas:**
  1. Criar `requirements-dev.txt` com `pytest` e `pytest-asyncio`.
  2. Criar `tests/conftest.py` com:
     - fixture `fake_session`: cria um `InspectionSession` e o vincula com
       `bind_inspection_session_context`;
     - fixture `fake_gcp`: substitui `backend.tools.cai_collector.gcp_rest_request`
       por um roteador em memória (URL e método para resposta);
     - fixture automática que falha o teste se `httpx` tentar sair para a rede.
  3. Observação: `backend.config` executa `settings.ensure_vertex_environment()` no
     import e `backend.agents.coordinator` cria `root_agent` no import. Os testes
     devem funcionar sem credenciais.
- **Critérios de aceite:**
  - [ ] `pytest -q` roda offline e passa com ao menos um teste de fumaça por fixture.
  - [ ] Um teste que chama `httpx.get` sem mock falha com mensagem clara.

## T01 — Kit de onboarding sem injeção

- **Prioridade:** P0. **Severidade:** CRITICAL. **Cobre:** C1.
- **Arquivos:**
  [onboarding_manager.py](../backend/tools/onboarding_manager.py#L224-L485) (`generate_customer_onboarding_kit`),
  [main.py](../backend/main.py#L641-L689) (rotas do kit; JS `downloadOnboardingZip`),
  [app.py](../frontend/app.py#L161-L200).
- **Problema:** campos do usuário entram crus em bash, HCL e Markdown. A PoC gerou
  uma linha `curl ... | bash` executável e `SEED_PROJECT_ID="${2:-$(touch /tmp/pwned)}"`.
- **Mudanças exigidas:**
  1. Validar no início de `generate_customer_onboarding_kit`, com `ValueError`:
     - `customer_name`: 1 a 80 caracteres, só letras, dígitos, espaço e `. , & ( ) - '`;
       sem quebras de linha nem caracteres de controle;
     - `organization_domain`: vazio ou nome DNS válido em minúsculas;
     - `seed_project_id`: vazio ou `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`;
     - `impersonator_user_email`: vazio ou e-mail válido, com prefixo opcional apenas
       `user:` ou `group:`; rejeitar `domain:`, `serviceAccount:`, `allUsers` e afins;
     - `onboarding_mode`: apenas `impersonated_sa` ou `direct_user`;
     - `sa_account_id`: `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`.
  2. Defesa em profundidade no bash: atribuir cada valor dinâmico uma única vez no
     topo com `shlex.quote` e referenciar só `"${VAR}"` no restante. Nenhum valor
     dinâmico em comentários, em strings de `echo` ou dentro de `${2:-...}`.
  3. No HCL: literais de string via `json.dumps`; nenhum valor dinâmico em comentários.
  4. Trocar `GET /api/v1/onboarding/download-kit` por POST com corpo JSON
     (`OnboardingKitRequest`), remover o GET e ajustar o JS para `fetch` + blob.
  5. Adicionar `max_length` e `pattern` aos campos de `OnboardingKitRequest`.
- **Critérios de aceite:**
  - [ ] Cada payload malicioso (quebra de linha, `$(...)`, crase, aspas, `;`,
        `domain:evil.com`) resulta em `ValueError` na função e HTTP 4xx na rota.
  - [ ] Para entradas válidas, `bash -n` no script retorna 0 e o conteúdo bate com
        um arquivo golden.
  - [ ] `GET /api/v1/onboarding/download-kit` retorna 405.
  - [ ] O gerador do Streamlit mostra o erro de validação em vez de gerar o kit.

## T02 — Deliverables por escopo, sem arquivo obsoleto

- **Prioridade:** P0. **Severidade:** CRITICAL. **Cobre:** C2.
- **Arquivos:**
  [main.py](../backend/main.py#L864-L998) (`get_posture_book`, `download_deliverable`),
  [report_generator.py](../backend/report_generator.py#L1525-L1587) (`generate_all_executive_deliverables_async`),
  [session_vault.py](../backend/session_vault.py#L190-L252) (`store_inspection_session`).
- **Problema:** DOCX, PDF e JSON de inventário têm nome fixo e só são regerados se
  não existirem. Reconectar não limpa o diretório.
- **Mudanças exigidas:**
  1. Em `store_inspection_session`, antes de gravar a nova sessão, apagar o diretório
     de export daquele `session_id` e chamar os hooks de purge.
  2. Gravar deliverables em subdiretório por escopo (hash do escopo canônico).
  3. Ao concluir `/api/v1/book`, persistir o book em `book.json` nesse subdiretório e
     invalidar DOCX, PDF e inventário daquele escopo.
  4. Extrair `render_deliverables_from_book(book, out_dir)`. O download gera a partir
     do `book.json` persistido, sem reexecutar a LLM. Sem book para o escopo, manter
     o comportamento atual (roda o scan).
  5. Regerar quando o `generated_at` do book for diferente do registrado no manifesto
     do arquivo.
  6. Responder downloads com `Cache-Control: no-store` e nome de arquivo contendo o
     id da organização e a data.
- **Critérios de aceite:**
  - [ ] Scan do escopo A, download, scan do escopo B, download: o segundo documento
        contém o escopo B e não o A.
  - [ ] Novo scan do mesmo escopo gera novo arquivo.
  - [ ] Após `store_inspection_session` com o mesmo sid, o diretório está vazio.
  - [ ] O download não chama o runner do ADK quando há `book.json` do escopo.

## T03 — Remover afirmações não verificadas

- **Prioridade:** P0. **Severidade:** HIGH. **Cobre:** H3.
- **Arquivos:**
  [recommender_tool.py](../backend/tools/recommender_tool.py#L110-L220) (`_collect_cloud_audit_usage_by_principal`),
  [recommender_tool.py](../backend/tools/recommender_tool.py#L398-L448) (`validate_remediation_with_policy_simulator`),
  [iac_generator.py](../backend/agents/iac_generator.py#L27-L60),
  [findings.py](../backend/models/findings.py#L223-L234) (`PolicySimulationValidation`),
  [report_generator.py](../backend/report_generator.py#L830-L856),
  [README.md](../README.md).
- **Problema:** nenhuma simulação é executada; a tool só lista replays existentes e
  os veredictos vêm da LLM. "30/90 dias" é uma página de 250 entradas de log.
- **Mudanças exigidas:**
  1. Renomear a tool para `collect_change_impact_evidence` e atualizar todas as
     referências (coordinator, iac_generator, instruções dos agentes, `tools/__init__`).
  2. Na coleta de logs: paginar até um teto configurável com orçamento de tempo e
     devolver `is_sample`, `sample_size`, início e fim reais da janela, e projetos
     consultados sobre o total. Renomear `cloud_audit_replay_baseline_90d` para
     `cloud_audit_log_sample`.
  3. Trocar o vocabulário de veredicto: remover `SAFE_TO_APPLY`; usar
     `NO_CONFLICT_IN_SAMPLE`, `REVIEW_REQUIRED`, `LIKELY_BREAKING`.
  4. Contagens exibidas ("chamadas testadas") devem vir do tamanho da amostra
     calculado em Python, nunca da LLM.
  5. Relatórios e UI: título da seção 6 passa a "Estimativa de impacto e bundle
     Terraform consultivo (não validado)". Remover "verified against Policy Simulator".
  6. Trocar rótulos "Audit30d", "30d Cloud Audit Logs" e "90d" por "eventos na
     amostra" com a janela real.
  7. Ajustar README e docs que descrevem replay de 90 dias.
- **Critérios de aceite:**
  - [ ] `grep -rn "verified against\|SAFE_TO_APPLY\|Audit30d" backend frontend` não
        retorna nada.
  - [ ] A saída da tool contém `is_sample`, `sample_size` e a janela.
  - [ ] Teste do gerador de relatório confere o novo título e a ausência da frase antiga.

## T04 — Autenticação

- **Prioridade:** P0. **Severidade:** HIGH. **Cobre:** H1, H2, M1.
- **Arquivos:**
  [identity_guard.py](../backend/identity_guard.py#L161-L352) (`verify_google_token`, `verify_iap_jwt_token`, `resolve_request_identity`),
  [main.py](../backend/main.py#L123-L183) (middleware),
  [main.py](../backend/main.py#L289-L481) (`verify_google_auth`, `logout_google_auth`, `oauth_bridge_popup`).
- **Problema:** tokens aceitos sem checar `aud`/`azp`; a ponte OAuth envia o token
  para qualquer origem `https`; o cookie prevalece sobre o IAP e não é revogado.
- **Mudanças exigidas:**
  1. ID token: exigir `audience=IAM_OAUTH_CLIENT_ID`. Sem client id configurado,
     rejeitar ID tokens. Remover o fallback por tokeninfo ou checar `aud` nele.
  2. Access token: exigir `azp` ou `aud` em uma allowlist formada por
     `IAM_OAUTH_CLIENT_ID` mais a variável `IAM_ALLOWED_TOKEN_AZP` (lista).
  3. Ponte OAuth: ignorar o parâmetro `origin`. `TARGET_ORIGIN` é a própria origem
     do serviço (variável `IAM_PUBLIC_ORIGIN` ou derivada da requisição). `localhost`
     só fora do Cloud Run.
  4. IAP: comparação exata de audiência. No Cloud Run sem `IAM_IAP_AUDIENCE`,
     ignorar o header e registrar aviso. Cachear as chaves públicas do IAP por 1h.
  5. Precedência: se há identidade IAP válida, o cookie só vale se o e-mail for o
     mesmo; caso contrário descartar o cookie e emitir outro com sid novo.
  6. Revogação: conjunto de sids revogados (com expiração) consultado em
     `verify_consultant_cookie`; logout e disconnect adicionam o sid.
  7. Tirar chamadas HTTP síncronas do event loop (`asyncio.to_thread`) e cachear
     verificações de Bearer bem-sucedidas por até 60s (chave: hash do token).
- **Confirmar antes:**
  - O valor de `azp` de um token de `gcloud auth print-access-token` (consultar
    tokeninfo) para preencher `IAM_ALLOWED_TOKEN_AZP`. Sem isso o fluxo de colar
    token deixa de funcionar.
  - O formato real do `aud` do IAP nativo do Cloud Run. Registre o `aud` recebido
    em caso de divergência antes de remover o fallback por prefixo.
- **Critérios de aceite:**
  - [ ] ID token com `aud` diferente do client id resulta em 401.
  - [ ] Access token com `azp` fora da allowlist resulta em 401.
  - [ ] `GET /api/v1/auth/bridge?origin=https://evil.example` renderiza
        `TARGET_ORIGIN` igual à própria origem.
  - [ ] Cookie do usuário A com JWT do IAP do usuário B resulta em identidade B e sid novo.
  - [ ] Após logout, o cookie antigo recebe 401 em `/api/v1/session/status`.

## T05 — Coleta completa e cobertura explícita

- **Prioridade:** P1. **Severidade:** HIGH. **Cobre:** H4, M6 (parte).
- **Arquivos:**
  [cai_collector.py](../backend/tools/cai_collector.py#L464-L810) (`_get_org_project_lifecycle_sets`, `_collect_single_leaf_bindings`, `_collect_single_leaf_resources`),
  [cai_collector.py](../backend/tools/cai_collector.py#L986-L1112) (`collect_cai_service_account_inventory`),
  [asset_key_secret_inventory.py](../backend/tools/asset_key_secret_inventory.py#L423-L459),
  [recommender_tool.py](../backend/tools/recommender_tool.py#L223-L395),
  [directory_collector.py](../backend/tools/directory_collector.py#L126-L166),
  [posture_scoring_engine.py](../backend/tools/posture_scoring_engine.py#L119-L149) (`_make_control`).
- **Problema:** limites fixos e silenciosos (1.500 policies, 2.000 recursos, 500
  projetos, 60 e 40 SAs, 40 roles, 100 usuários); erro de API vira lista vazia;
  população vazia pontua 100%.
- **Mudanças exigidas:**
  1. Paginador central com teto configurável, orçamento de tempo e retry com backoff
     para 429 e 5xx. Retorna itens e um `CollectionStatus` (completo, páginas, erro
     HTTP, motivo do corte).
  2. Registrar o status de cada coletor em um mapa de cobertura do scan, cacheado
     junto com os dados.
  3. Erro HTTP nunca vira lista vazia: registrar o erro na cobertura.
  4. Remover os cortes fixos. Onde um teto permanecer por custo, registrar
     "avaliados X de Y".
  5. Metadados de roles: garantir que roles predefinidas (`roles/*`) nunca sejam
     cortadas pela ordenação alfabética.
  6. Chaves de SA: uma única função usada pelo score e pelo inventário. SA cuja
     consulta de chaves falhou conta como "desconhecida", não como "sem chave".
  7. Score: controle com dado incompleto ou indisponível recebe `NOT_EVALUATED` e
     sai da média com renormalização dos pesos. População realmente vazia (com
     cobertura completa) mantém aprovação, com evidência "0 itens no escopo".
  8. `PostureScorecard` ganha `coverage_warnings` e `data_completeness_pct`. Com
     coleta de bindings ou de chaves incompleta, o tier máximo é "Managed".
  9. UI, DOCX e PDF mostram um aviso no topo quando houver `coverage_warnings`.
- **Critérios de aceite:**
  - [ ] Sete páginas de policies são todas coletadas, com cobertura completa.
  - [ ] 403 em `searchAllResources` no escopo da organização: cobertura marcada como
        falha, controles WKL como `NOT_EVALUATED`, aviso presente, score não tratado como 100%.
  - [ ] 200 SAs com chave de mais de 90 dias na 150ª: o teto crítico dispara.
  - [ ] Teto atingido gera aviso com os números avaliados e totais.
  - [ ] Inventário e scorecard reportam a mesma contagem de chaves de usuário.

## T06 — Terraform determinístico

- **Prioridade:** P1. **Severidade:** HIGH. **Cobre:** H5.
- **Arquivos:**
  [iac_generator.py](../backend/agents/iac_generator.py),
  [coordinator.py](../backend/agents/coordinator.py#L534-L571) (`run_iac_assessment`),
  [recommender_tool.py](../backend/tools/recommender_tool.py#L451-L532) (`inspect_iac_target_environment`, `package_terraform_remediation_files`),
  [findings.py](../backend/models/findings.py#L599-L608) (`IaCAgentOutput`).
- **Problema:** HCL livre da LLM é gravado sem validação; metadados do cliente
  (nomes de exibição) entram no prompt.
- **Mudanças exigidas:**
  1. A LLM passa a devolver um plano estruturado (`IaCPlan`) com ações tipadas:
     aplicar org policy, criar entitlement PAM, substituir role, criar custom role.
  2. Python valida cada campo: principal e role devem existir nos bindings coletados;
     role segue o padrão de nome de role; constraint pertence a
     `KEY_IAM_ORG_CONSTRAINTS`; recurso pertence ao escopo; e-mails válidos.
  3. Recusar ações que concedam `roles/owner`, `roles/editor` ou roles de admin de IAM.
  4. Python renderiza o HCL a partir de templates fixos, com literais via `json.dumps`.
     Só recursos não autoritativos (`google_*_iam_member`); sem `provisioner`, data
     sources, módulos ou `*_iam_policy` / `*_iam_binding`.
  5. Remoções de binding vão para `MANUAL_STEPS.md` como comandos `gcloud` com
     `shlex.quote`.
  6. Cabeçalho em cada arquivo: "RASCUNHO CONSULTIVO, NÃO VALIDADO. Revisar antes
     de aplicar." Ajustar rótulos de UI e relatório.
  7. Remover `display_name` da saída de `inspect_iac_target_environment` e instruir
     os agentes a tratar metadados como dados, nunca como instruções.
- **Alternativa (se a decisão for manter HCL da LLM):** analisar com `python-hcl2`,
  aplicar allowlist de tipos de recurso e as mesmas proibições do item 4.
- **Critérios de aceite:**
  - [ ] Plano com principal inexistente nos bindings é rejeitado.
  - [ ] Plano que concede `roles/owner` é rejeitado.
  - [ ] O HCL gerado é analisável e contém apenas tipos de recurso da allowlist.
  - [ ] Texto malicioso em nome de exibição de SA não aparece em nenhum arquivo gerado.

## T07 — Grounding da saída da LLM

- **Prioridade:** P1. **Severidade:** HIGH. **Cobre:** H6.
- **Arquivos:**
  [coordinator.py](../backend/agents/coordinator.py#L275-L531) (`run_triad_assessment`, `_run_attack_path_assessment_internal`, `_run_recommender_assessment_internal`),
  [coordinator.py](../backend/agents/coordinator.py#L666-L702).
- **Problema:** achados, caminhos e contagens vêm da LLM sem conferência.
- **Mudanças exigidas:**
  1. Achados: principal deve existir nos bindings ou no inventário; role, se
     informada, deve existir para aquele principal; recurso dentro do escopo. O que
     não confere é descartado e contado em `ungrounded_findings_dropped`.
  2. Caminhos de ataque: cada par consecutivo de `hop_sequence` deve ser aresta do
     grafo. `toxic_combinations_count` e `escalation_paths_count` calculados em Python.
  3. Recomendações: `permissions_granted_count` sobrescrito com o valor da API de
     roles; o uso observado sobrescrito com a amostra de logs; principal e role
     atuais devem existir nos bindings.
  4. Ids de achado renumerados de forma determinística e sem duplicatas.
  5. Contagens de severidade calculadas depois do grounding.
  6. Expor na telemetria quantos itens foram descartados por agente.
- **Critérios de aceite:**
  - [ ] Achado com principal inventado é descartado e as contagens se ajustam.
  - [ ] Caminho com aresta inexistente é descartado.
  - [ ] Recomendação com contagem de permissões inventada é corrigida para o valor real.

## T08 — Execução, timeouts e limites do grafo

- **Prioridade:** P1. **Severidade:** HIGH. **Cobre:** H7.
- **Arquivos:**
  [coordinator.py](../backend/agents/coordinator.py#L574-L776) (`run_posture_book_assessment`),
  [telemetry.py](../backend/agents/telemetry.py#L229-L298) (`execute_adk_agent`, `run_async_from_sync`),
  [graph_engine.py](../backend/tools/graph_engine.py#L412-L552),
  [main.py](../backend/main.py#L777-L998),
  [report_generator.py](../backend/report_generator.py#L1525-L1587).
- **Problema:** chamadas síncronas pesadas dentro de `async`; sem timeout por agente;
  enumeração de caminhos sem limite (PoC: 2.080 nós não terminou em 45s);
  `refresh=true` refaz a coleta 4 a 5 vezes.
- **Mudanças exigidas (parte A):**
  1. Envolver em `asyncio.to_thread` toda coleta, construção de grafo, renderização
     de PNG, DOCX e PDF chamada de funções `async`.
  2. Tools do ADK: transformar em `async def` que delega a implementação síncrona
     para uma thread.
  3. `render_attack_graph_png`: usar a API orientada a objetos do matplotlib
     (`Figure` + `FigureCanvasAgg`), sem `pyplot`.
  4. `force_refresh` aplicado uma única vez por scan; as sub-avaliações reutilizam
     os dados já coletados.
  5. `execute_adk_agent` com `asyncio.wait_for` (timeout configurável) e limite de
     chamadas de LLM por execução. Timeout vira 504 com mensagem clara.
  6. `extract_raw_topological_paths`: limitar fontes e alvos por prioridade de risco,
     orçamento de tempo global e número máximo de candidatos. Aplicar o mesmo
     helper nos laços do score.
  7. Betweenness amostrado (`k`) acima de 500 nós. Cachear o grafo por sessão e escopo.
  8. `analyze_iam_attack_paths`: enviar à LLM um subconjunto de nós e arestas mais
     os totais, não o grafo inteiro.
  9. `run_async_from_sync`: propagar o contexto (`contextvars.copy_context().run`).
- **Mudanças exigidas (parte B, PR separado):**
  1. `POST /api/v1/scans` devolve `scan_id` e executa em background; a UI consulta
     `GET /api/v1/scans/{id}`.
  2. Deploy com CPU sempre alocada para o trabalho em background.
- **Confirmar antes:** suporte a tools `async` e a limite de chamadas de LLM
  (`RunConfig`) na versão instalada do ADK (2.14.1).
- **Critérios de aceite:**
  - [ ] `/health` responde em menos de 200 ms enquanto um scan falso de 2s está em curso.
  - [ ] Grafo sintético de 2.080 nós (o da PoC) termina em menos de 15s.
  - [ ] Agente falso que trava resulta em 504 dentro do timeout.
  - [ ] Um scan com `refresh=true` chama a coleta de bindings uma única vez.

## T09 — Estado e wipe

- **Prioridade:** P1. **Severidade:** HIGH. **Cobre:** H8, M2.
- **Arquivos:**
  [session_vault.py](../backend/session_vault.py#L180-L332),
  [coordinator.py](../backend/agents/coordinator.py#L95-L104),
  [main.py](../backend/main.py#L88),
  [02_deploy_cloud_run.sh](../scripts/02_deploy_cloud_run.sh#L154-L173).
- **Problema:** estado em memória de um processo com até 4 instâncias; histórico de
  chat e tokens pendentes sobrevivem ao wipe.
- **Mudanças exigidas:**
  1. Deploy: `--max-instances=1`, afinidade de sessão e `--min-instances=1`
     (documentar o custo).
  2. Chat: um serviço de sessão do ADK por sessão do cofre, removido no hook de purge.
  3. Tokens pendentes: mover para `session_vault`, vincular a (sid, e-mail), expirar
     por TTL e remover no purge.
  4. `wipe_inspection_session`: só apagar diretório e caches quando o dono confere.
     Usar o mesmo id sanitizado em todos os `rmtree`.
  5. Tarefa periódica (lifespan do FastAPI) que purga sessões expiradas mesmo sem tráfego.
  6. UI: mensagem específica quando a sessão não existe mais no servidor.
- **Critérios de aceite:**
  - [ ] Após o wipe não há sessão de chat nem token pendente para o sid.
  - [ ] Token pendente expirado é removido pela tarefa periódica.
  - [ ] Wipe com dono incorreto não apaga o diretório.

## T10 — Relatórios robustos

- **Prioridade:** P1. **Severidade:** HIGH. **Cobre:** H9, M14.
- **Arquivo:**
  [report_generator.py](../backend/report_generator.py).
- **Problema:** `LayoutError` no PDF com cerca de 40 achados ou 120 roles em uma
  célula; `ValueError` no DOCX com caractere de controle; DOCX quadrático; fontes
  do PDF sem Unicode; UI, DOCX e PDF divergem.
- **Mudanças exigidas:**
  1. Roadmap: uma linha por ação em vez de uma célula por wave (`_build_wave_rows`).
  2. Listas longas em célula (roles, accessors): limitar itens exibidos com "+N" e
     usar divisão de linha na tabela. Se ainda ocorrer `LayoutError`, reconstruir a
     tabela com células truncadas.
  3. Função única de limpeza de texto que remove caracteres inválidos em XML 1.0,
     aplicada a todo texto do DOCX e do PDF.
  4. `_add_docx_grid_table`: obter as linhas uma vez e `row.cells` uma vez por linha.
  5. PDF: registrar fonte TTF Unicode (regular, negrito, mono) e usá-la em todos os
     estilos. Incluir os arquivos de fonte e a licença no repositório.
  6. Narrativa: converter títulos, listas e negrito do Markdown em vez de imprimir
     os marcadores.
  7. Um único modelo de visão (`report_view_model(book)`) com seções, colunas e
     linhas, consumido pelos dois geradores.
  8. Truncamentos: guardar o total real (por exemplo `accessor_principals_total`) e
     usar a mesma quantidade exibida em UI, DOCX e PDF.
  9. Org policy não avaliada: mesmo rótulo nos três lugares.
  10. DOCX e PDF gerados de forma independente; a falha de um não bloqueia o outro.
- **Confirmar antes:** disponibilidade de `splitInRow` em `Table` no ReportLab 5.1.0.
- **Critérios de aceite:**
  - [ ] PDF com 80 achados na mesma wave é gerado.
  - [ ] PDF com um principal de 300 roles é gerado.
  - [ ] DOCX com `\x0b` no texto é gerado.
  - [ ] DOCX com 2.000 contas é gerado em menos de 3s (hoje 12,9s).
  - [ ] PDF com texto "日本語 →" é gerado com a fonte Unicode embutida.
  - [ ] Teste do modelo de visão: DOCX e PDF têm os mesmos cabeçalhos por seção.

## T11 — Correções do score

- **Prioridade:** P2. **Severidade:** MEDIUM. **Cobre:** M5, M6.
- **Arquivos:**
  [posture_scoring_engine.py](../backend/tools/posture_scoring_engine.py#L88-L116),
  [posture_scoring_engine.py](../backend/tools/posture_scoring_engine.py#L981-L1057) (`synthesize_final_framework_scorecard`),
  [findings.py](../backend/models/findings.py#L535-L596),
  [main.py](../backend/main.py#L3498-L3518) (`renderFrameworkScorecardUI`).
- **Mudanças exigidas:**
  1. Separar os números: `agentic_calibration_delta` (sempre em ±5),
     `critical_cap_delta` (zero ou negativo) e `pre_cap_score`. UI e relatórios
     mostram baseline, calibração e efeito do teto.
  2. `_clamp`: valores não finitos viram 0.
  3. Schemas dos agentes: trocar `ge`/`le` do delta por validador que faz clamp.
  4. `_has_temporal_jit_condition`: exigir limite superior
     (`request.time <` ou `<=` seguido de `timestamp(`).
  5. `deterministic_maturity_tier` também respeita o teto.
  6. INT-04: sem Directory API, o controle não pode sair como PASS de MFA; marcar
     dado parcial com evidência explícita.
  7. GRP-02 e GRP-03: normalizar pelo tamanho do ambiente (caminhos por 100
     principals de entrada; nós de ACL de conveniência por projeto). Registrar a
     mudança em `methodology_version`.
  8. LPI-03: numerador e denominador sobre a mesma população.
  9. Limiar único para "aprovado" (hoje 85 no controle e 80 no benchmark) e
     docstrings corrigidas de 16 para 18 controles.
- **Critérios de aceite:**
  - [ ] Caso da PoC (baseline 92,3 com teto): calibração 0,0, efeito do teto -8,3, final 84,0.
  - [ ] Delta NaN resulta em 0; delta 7,5 da LLM vira 5,0 sem exceção.
  - [ ] Condição `request.time > timestamp("2020-01-01T00:00:00Z")` não conta como JIT.
  - [ ] Teste confere que os pesos somam 100% por domínio e no composto.

## T12 — Classificação de principals e grafo

- **Prioridade:** P2. **Severidade:** MEDIUM. **Cobre:** M7, M8, M9.
- **Arquivos:**
  [cai_collector.py](../backend/tools/cai_collector.py#L101-L111),
  [cai_collector.py](../backend/tools/cai_collector.py#L370-L444),
  [asset_key_secret_inventory.py](../backend/tools/asset_key_secret_inventory.py#L53-L97),
  [graph_engine.py](../backend/tools/graph_engine.py#L208-L387),
  [onboarding_manager.py](../backend/tools/onboarding_manager.py#L165-L197).
- **Mudanças exigidas:**
  1. Tirar `@appspot.gserviceaccount.com` e `@cloudbuild.gserviceaccount.com` dos
     padrões de agente Google; tratá-las como SAs padrão.
  2. SA cujo projeto não pertence à organização é externa. Com lista de projetos
     incompleta, marcar "desconhecido".
  3. Sessão guarda um conjunto de domínios da organização. Sem domínio, classificar
     como "desconhecido" e avisar, nunca como interno.
  4. Principals `deleted:` têm tipo próprio e não contam como externos.
  5. Acesso a secrets e uso de KMS derivados de `includedPermissions` das roles
     (API de roles e custom roles do CAI), não de listas fixas. Remover `roles/editor`
     dos leitores de secret.
  6. Binding de pasta vale só para os projetos daquela pasta.
  7. Chave sem `keyType` é "UNKNOWN" com risco alto, não `SYSTEM_MANAGED`.
  8. Grafo: SAs indexadas pelo projeto de origem; arestas workload para SA também a
     partir de `versioned_resource` (helper compartilhado com o inventário).
  9. Fallback de descoberta de projetos: filtrar por ancestralidade da organização;
     se não for possível determinar, não listar e avisar.
- **Critérios de aceite:**
  - [ ] SA padrão do App Engine com `roles/editor` aparece nos bindings do cliente e no WKL-03.
  - [ ] SA de projeto fora da organização é marcada como externa.
  - [ ] `roles/editor` no projeto não torna o principal leitor de secrets.
  - [ ] TokenCreator no projeto B não cria aresta para SA do projeto A.
  - [ ] VM com SA anexada gera aresta workload para SA.
  - [ ] Projeto de outra organização não aparece no seletor.

## T13 — Validação de escopo e caches

- **Prioridade:** P1. **Severidade:** MEDIUM. **Cobre:** M3, M4.
- **Arquivos:**
  [cai_collector.py](../backend/tools/cai_collector.py#L141-L367) (`parse_assessment_scope`, `gcp_rest_request`),
  [onboarding_manager.py](../backend/tools/onboarding_manager.py#L73-L77),
  [session_vault.py](../backend/session_vault.py#L113-L139),
  [recommender_tool.py](../backend/tools/recommender_tool.py#L59-L107) (`get_live_role_metadata`).
- **Problema:** a PoC transformou um escopo em POST para `:setIamPolicy`; tools
  aceitam qualquer escopo vindo da LLM; cache global de roles guarda erros.
- **Mudanças exigidas:**
  1. Validadores estritos: id de organização e de pasta só dígitos; id de projeto
     `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`; e-mail de SA; partes da tabela do BigQuery.
     Erro vira HTTP 400.
  2. Montar URLs com `urllib.parse.quote(segmento, safe="")`.
  3. Guarda de leitura em `gcp_rest_request`: allowlist de hosts e, para POST,
     allowlist de sufixos (`:getIamPolicy`, `:getEffectiveOrgPolicy`, `entries:list`,
     `:generateAccessToken`, `insertAll`). Qualquer outro POST levanta erro.
  4. Escopo permitido por requisição em contexto; tools chamadas pela LLM só aceitam
     escopo igual ou contido no permitido.
  5. `_ROLE_META_CACHE` guarda apenas respostas bem-sucedidas.
- **Critérios de aceite:**
  - [ ] `projects/victim-proj:setIamPolicy?x=` resulta em `ValueError`.
  - [ ] POST para caminho fora da allowlist levanta erro antes de sair para a rede.
  - [ ] Tool chamada com organização diferente da sessão é rejeitada.
  - [ ] 403 de uma sessão não afeta a resposta de outra sessão para a mesma role.

## T14 — Superfície web

- **Prioridade:** P2. **Severidade:** MEDIUM. **Cobre:** M12, L5, L6.
- **Arquivo:**
  [main.py](../backend/main.py).
- **Mudanças exigidas:**
  1. Middleware de headers: `X-Content-Type-Options: nosniff`, `frame-ancestors 'none'`,
     `Referrer-Policy: no-referrer`, HSTS. CSP em modo Report-Only nesta tarefa.
  2. `escHtml` passa a escapar aspas simples e duplas. Trocar o `onchange` com id de
     projeto interpolado por `data-*` e listener.
  3. `/api/docs`, `/api/redoc` e `/openapi.json` desativados no Cloud Run.
  4. `/health` devolve só o status. Nunca devolver `session_id`.
  5. Remover caminhos do servidor das respostas (`bundle_zip_path`,
     `deliverable_paths`, `session_jsonl_path`).
  6. Operações caras ou com efeito colateral só por POST e com header
     `X-Requested-With`.
  7. CORS para `localhost` só fora do Cloud Run.
  8. Cookie com caractere não ASCII é tratado como inválido (hoje gera 500).
  9. Erros ao cliente com mensagem genérica e id de correlação; detalhe só no log.
     A resposta 403 de domínio não lista os domínios permitidos.
  10. Limite por usuário para scans e chat (configurável).
- **Fora de escopo:** migrar os handlers inline para permitir CSP estrita (tarefa futura).
- **Critérios de aceite:**
  - [ ] Respostas HTML têm os headers do item 1.
  - [ ] `/health` não contém `session_id` nem e-mail.
  - [ ] Com `K_SERVICE` definido, `/api/docs` retorna 404.
  - [ ] Cookie com bytes não ASCII retorna 401, não 500.
  - [ ] `GET /api/v1/book?refresh=true` não dispara scan.
  - [ ] Excedido o limite, a rota retorna 429.

## T15 — Scripts de deploy

- **Prioridade:** P2. **Severidade:** MEDIUM. **Cobre:** M11.
- **Arquivos:**
  [02_deploy_cloud_run.sh](../scripts/02_deploy_cloud_run.sh),
  [01_bootstrap_gcp.sh](../scripts/01_bootstrap_gcp.sh#L141-L170).
- **Mudanças exigidas:**
  1. Remover padrões fixos (`ACCOUNT`, `ORG_DOMAIN`, principals pessoais,
     `domain:google.com`, client id OAuth). Variáveis obrigatórias com `${VAR:?}`.
  2. `roles/run.invoker` apenas para o agente de serviço do IAP.
  3. Acesso ao IAP a partir de `IAP_MEMBERS` (lista), no nível do serviço e não do
     projeto. `allAuthenticatedUsers` só com `ALLOW_ANY_GOOGLE_ACCOUNT=true`.
  4. `ALLOWED_IAP_DOMAINS` vindo de variável, sem `*` por padrão.
  5. Tirar `roles/storage.admin` da SA padrão do Compute.
  6. Remover `|| true` dos bindings de segurança e mostrar as falhas.
  7. `trap` para apagar o YAML temporário com o client secret.
  8. Bootstrap: SA de runtime só com `aiplatform.user` e `logging.logWriter`.
     Documentar os comandos para revogar os grants antigos (não executar).
  9. Modo `DRY_RUN=1` que só imprime os comandos.
- **Critérios de aceite:**
  - [ ] `bash -n` e `shellcheck` sem erros nos dois scripts.
  - [ ] `grep` em `scripts/` não retorna contas pessoais, domínios corporativos nem IDs de cliente OAuth hardcoded.
  - [ ] Sem as variáveis obrigatórias o script falha antes de qualquer comando `gcloud`.
  - [ ] `DRY_RUN=1` não executa nenhum comando.

## T16 — Higiene do repositório

- **Prioridade:** P2. **Severidade:** MEDIUM. **Cobre:** M13, M15.
- **Mudanças exigidas:**
  1. `git rm -r --cached exports/` (mantém os arquivos locais). Não reescrever o
     histórico; documentar o comando para o dono do repositório decidir.
  2. Fixar as dependências diretas nas versões instaladas e gerar um lock:
     google-adk 2.14.1, google-genai 2.34.0, fastapi 0.162.0, starlette 1.10.0,
     pydantic 2.14.3, httpx 0.28.1, google-auth 2.62.2, reportlab 5.1.0,
     python-docx 1.2.0, networkx 3.7, matplotlib 3.11.2, uvicorn 0.54.0,
     streamlit 1.67.0.
  3. Workflow de CI que roda `pytest` e `shellcheck`.
  4. Remover `curl` do Dockerfile.
- **Critérios de aceite:**
  - [ ] `git ls-files exports` não retorna nada e os arquivos continuam no disco.
  - [ ] Instalação a partir do lock em ambiente limpo e `pytest -q` verde.

## T17 — Limpeza de itens LOW (opcional)

- **Prioridade:** P3. **Cobre:** L1–L4, L7–L10.
- **Mudanças exigidas:**
  1. Remover código morto: reuso de `existing_sid`, refresh de token de SA que nunca
     funciona, ramo `gemini-4`, campo `last_authenticated_time`.
  2. Probe de descoberta: medir latência e status reais em vez de `95` e 200/403 fixos.
  3. Remover fallbacks para variáveis do host (`GCP_ORGANIZATION_ID`, projeto padrão,
     diretório de export compartilhado) nos caminhos web.
  4. Export para BigQuery: validar o nome da tabela, usar `insertId` para evitar
     duplicatas e mostrar o status na UI.
  5. Streamlit: renderizar saída da LLM sem carregar imagens remotas.
  6. PDF: preservar a proporção do PNG. Grafo: desativar mathtext nos rótulos.
  7. Modo `direct_user`: usar a expiração real do token (tokeninfo) em vez de 1h.
  8. `set_active_model`: não alterar estado global por requisição.
- **Critérios de aceite:**
  - [ ] Cada item tem um teste ou uma verificação descrita no PR.
