# Report Labels & Glossary (EN / PT-BR)

`report-synthesizer` renders `report-template.md` and `report-template.html` once per language. Every `{{KEY}}` token in those templates is replaced with the value from the matching column below. Both languages come from the same findings and the same structure: only the labels and the prose change.

Rules:
- Keep every key, enum value and finding ID identical across languages. `scripts/check_report_parity.py` fails if the two renderings disagree on finding IDs, CVSS vectors, scores or status counts.
- Do not translate finding IDs, CWE IDs, MASVS IDs, reference IDs (`WEB-02`), CVSS vectors, file paths, package names, or code identifiers.
- Output files: `report/final-report.en.md`, `report/final-report.en.html`, `report/final-report.pt-BR.md`, `report/final-report.pt-BR.html`.

## Labels

| Key | EN | PT-BR |
|---|---|---|
| `LANG` | en | pt-BR |
| `H_TITLE` | Mobile Application Security Assessment | Avaliação de Segurança de Aplicação Mobile |
| `L_APP` | Application | Aplicativo |
| `L_BUILD` | Build | Build |
| `L_PLATFORMS` | Platform(s) | Plataforma(s) |
| `L_FRAMEWORK` | Framework | Framework |
| `L_ARTIFACT_SHA256` | Artifact SHA-256 | SHA-256 do artefato |
| `L_WINDOW` | Assessment window | Período da avaliação |
| `L_TOOLS` | Tools and versions | Ferramentas e versões |
| `L_CLASSIFICATION` | Report classification | Classificação do relatório |
| `CLASSIFICATION_VALUE` | Confidential: contains unpatched vulnerability details | Confidencial: contém detalhes de vulnerabilidades não corrigidas |
| `L_AUTHORIZATION` | Authorization and scope | Autorização e escopo |
| `S_EXEC` | Executive summary | Sumário executivo |
| `S_SCOPE` | Scope and authorization | Escopo e autorização |
| `S_METHOD` | Methodology | Metodologia |
| `S_COVERAGE` | MASVS coverage | Cobertura MASVS |
| `S_SUMMARY` | Findings summary | Resumo dos achados |
| `S_CONFIRMED` | Confirmed findings | Achados confirmados |
| `S_POTENTIAL` | Potential findings | Achados potenciais |
| `S_INFO` | Informational and hardening observations | Observações informativas e de hardening |
| `S_PLAN` | Prioritized remediation plan | Plano de remediação priorizado |
| `S_APPX_A` | Appendix A: False positives and ruled out | Apêndice A: Falsos positivos e itens descartados |
| `S_APPX_B` | Appendix B: Attack surface inventory | Apêndice B: Inventário da superfície de ataque |
| `S_APPX_C` | Appendix C: Methodology and limitations | Apêndice C: Metodologia e limitações |
| `S_APPX_D` | Appendix D: Glossary | Apêndice D: Glossário |
| `S_APPX_E` | Appendix E: Comparison with previous audit | Apêndice E: Comparação com auditoria anterior |
| `H_NUM` | # | # |
| `H_FINDING` | Finding | Achado |
| `H_SEVERITY` | Severity | Severidade |
| `H_STATUS` | Status | Status |
| `H_ATTACKER` | Attacker model | Modelo de atacante |
| `H_CVSS` | CVSS 3.1 | CVSS 3.1 |
| `H_REFS` | Ref IDs | IDs de referência |
| `H_PRIORITY` | Priority | Prioridade |
| `H_ACTION` | Action | Ação |
| `H_VERIFY` | Acceptance criterion (retest) | Critério de aceite (reteste) |
| `H_SUSPECTED` | What was suspected | O que foi suspeitado |
| `H_REFUTATION` | Why the refutation held | Por que a refutação se sustentou |
| `H_COVERAGE_AREA` | MASVS control | Controle MASVS |
| `H_COVERAGE_STATUS` | Coverage | Cobertura |
| `H_COVERAGE_FINDINGS` | Findings | Achados |
| `H_GLOSSARY_TERM` | Term | Termo |
| `H_GLOSSARY_MEANING` | Meaning | Significado |
| `L_SEVERITY` | Severity | Severidade |
| `L_STATUS` | Status | Status |
| `L_ATTACKER` | Attacker model | Modelo de atacante |
| `L_CWE` | CWE | CWE |
| `L_CVSS` | CVSS 3.1 vector and score | Vetor e score CVSS 3.1 |
| `L_MASVS` | MASVS | MASVS |
| `L_REFS` | Ref IDs | IDs de referência |
| `L_DESCRIPTION` | Description | Descrição |
| `L_ATTACK_PATH` | Attack path | Caminho de ataque |
| `L_REPRO_STATIC` | Reproduction (static) | Reprodução (estática) |
| `L_REPRO_DYNAMIC` | Reproduction (dynamic) | Reprodução (dinâmica) |
| `L_EVIDENCE` | Evidence | Evidências |
| `L_PANEL` | Exploitation panel verdict | Veredito do painel adversarial |
| `L_REMEDIATION` | Remediation | Remediação |
| `L_ACCEPTANCE` | Acceptance criterion | Critério de aceite |
| `L_SEVERITY_NOTE` | Severity note | Nota sobre a severidade |
| `L_WHY_NOT_CONFIRMED` | Why it is not Confirmed | Por que não está Confirmado |
| `L_CANDIDATE_NOTE` | Not reviewed by the exploitation panel | Não revisado pelo painel adversarial |
| `L_TRANSCRIPT` | Full transcript | Transcrição completa |
| `L_SUSPECTED` | Suspected | Suspeita |
| `L_DEFEATING_FACT` | Defeating fact | Fato decisivo |
| `NONE_IDENTIFIED` | None identified. | Nenhum identificado. |
| `NOT_APPLICABLE` | Not applicable. | Não se aplica. |
| `PENDING_RETEST` | Pending retest | Aguardando reteste |

## Enum labels

| Value | EN | PT-BR |
|---|---|---|
| severity `critical` | Critical | Crítica |
| severity `high` | High | Alta |
| severity `medium` | Medium | Média |
| severity `low` | Low | Baixa |
| severity `info` | Info | Informativa |
| status `confirmed` | Confirmed | Confirmado |
| status `potential` | Potential | Potencial |
| status `informational` | Informational | Informativo |
| status `false-positive` | False Positive | Falso positivo |
| status `candidate` | Candidate | Candidato |
| status `under-review` | Under review | Em análise |
| attacker `remote` | remote | remoto |
| attacker `other-app` | other app on device | outro app no dispositivo |
| attacker `physical` | physical access | acesso físico |
| attacker `local-root` | local, rooted device | local, com root |
| attacker `none` | none | nenhum |
| coverage `tested` | Tested | Testado |
| coverage `partial` | Partial | Parcial |
| coverage `not-tested` | Not tested | Não testado |
| priority `P1` | P1, fix now | P1, corrigir agora |
| priority `P2` | P2, next release | P2, próxima release |
| priority `P3` | P3, backlog | P3, backlog |

## Glossary (Appendix D source)

| Term | EN meaning | PT-BR meaning |
|---|---|---|
| Confirmed | Exploitable by the stated attacker model in this build, with dynamic or unambiguous static evidence, and the panel's refutation attempts failed. | Explorável pelo modelo de atacante declarado nesta build, com evidência dinâmica ou estática inequívoca, e as tentativas de refutação do painel falharam. |
| Potential | Plausible and worth fixing, but the loop could not be closed. The report states what would upgrade it. | Plausível e vale corrigir, mas o ciclo não pôde ser fechado. O relatório diz o que o confirmaria. |
| Informational | Best-practice or hardening observation without a credible attacker model in this context. | Observação de boa prática ou hardening sem modelo de atacante crível neste contexto. |
| False positive | The panel's refutation showed the path is closed or unreachable. Kept in Appendix A to show what was checked. | O painel mostrou que o caminho está fechado ou inalcançável. Mantido no Apêndice A para mostrar o que foi verificado. |
| Candidate | Raised by a specialist and not yet reviewed by the panel. Not a verdict. | Levantado por um especialista e ainda não revisado pelo painel. Não é veredito. |
| Attacker model | Who can perform the attack: remote, another app on the device, physical access, or a rooted device. | Quem pode executar o ataque: remoto, outro app no dispositivo, acesso físico ou dispositivo com root. |
| CVSS 3.1 | Standard base score computed from the vector. It describes the attack and impact; it does not decide the status. | Score base padrão calculado a partir do vetor. Descreve ataque e impacto; não decide o status. |
| Severity note | Explanation shown when the CVSS band and the panel's severity differ by one band or more. | Explicação exibida quando a faixa CVSS e a severidade do painel diferem em uma faixa ou mais. |
| MASVS | OWASP Mobile Application Security Verification Standard, the control set this report is organized by. | Padrão de verificação de segurança do OWASP Mobile, o conjunto de controles usado para organizar este relatório. |
| MASTG | OWASP Mobile Application Security Testing Guide, the test procedures behind MASVS. | Guia de testes do OWASP Mobile, os procedimentos de teste por trás do MASVS. |
| CWE | Common Weakness Enumeration, the weakness class of the root cause. | Common Weakness Enumeration, a classe de fraqueza da causa raiz. |
| Well-evidenced refutation | A skeptic's refutation that cites a specific, checkable fact breaking a step of the prosecutor's path. | Refutação do cético que cita um fato específico e verificável que quebra um passo do caminho do promotor. |
| Acceptance criterion | The observable check that proves a fix works on retest. | A verificação observável que prova que a correção funciona no reteste. |
