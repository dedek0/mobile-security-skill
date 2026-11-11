# Avaliação de Segurança de Aplicação Mobile: VulnBank Demo (build desconhecido)

> Confidencial: contém detalhes de vulnerabilidades não corrigidas

| | |
|---|---|
| **Plataforma(s)** | Somente Android. Nenhum artefato iOS foi fornecido. |
| **Framework** | Android nativo (Java/Kotlin), presumido pelos nomes de classe. Não verificado: nenhum DEX ou código-fonte foi fornecido. |
| **SHA-256 do artefato** | `unknown` (não registrado em `target-profile.md`) |
| **Período da avaliação** | 2026-10-08 a 2026-10-09 (`scope.md` datado de 2026-10-08; sessão dinâmica em 2026-10-09) |
| **Autorização e escopo** | App próprio. Um fixture de teste sintético escrito pelo mantenedor do repositório (ver `scope.md`). |
| **Ferramentas e versões** | adb 1.0.41 (platform-tools 35.0.2-12147458). apktool, jadx e aapt2 estão no host, mas não foram executados, porque não existe APK. Revisão manual de `AndroidManifest.xml`. `scripts/cvss31.py` (versão não registrada). |

## Sumário executivo

Nenhum achado chegou a Confirmado. Dois achados estão como Potencial e com severidade Alta: uma deep link exportada e navegável para uma tela de transferência sem guarda de permissão (AND-MAN-003), e uma flag de depuração que permitiria a uma sessão ADB autorizada ler a sandbox do app (AND-MAN-001). Nenhum dos dois pôde ser fechado com as evidências disponíveis, porque o app nunca foi instalado no aparelho de teste e nenhum código de implementação foi fornecido. Quatro itens são candidatos que o painel não revisou, incluindo um provider exportado sem guarda, classificado como Alta na primeira avaliação (AND-MAN-004). Corrija as flags do manifesto antes de qualquer build de release, e coloque uma guarda de permissão e uma reautenticação dentro do app no caminho de transferência.

**Contagens** (severidade é `final_severity` para achados revisados pelo painel e `severity_initial` para candidatos):
- Por severidade: Crítica 0 · Alta 3 · Média 1 · Baixa 1 · Informativa 1
- Por status: Confirmado 0 · Potencial 2 · Informativo 0 · Falso positivo 0 · Candidato 4
- Problemas distintos: 6 (sem fusões, ver Apêndice C)

**Principais riscos:** AND-MAN-003 (Potencial, Alta, CVSS 7.1) · AND-MAN-001 (Potencial, Alta, CVSS 5.9) · AND-MAN-004 (Candidato, Alta na primeira avaliação, CVSS 7.7, não revisado pelo painel)

## Escopo e autorização

Alvo: VulnBank Demo (`com.vulnbankdemo.app`), um fixture de manifesto sintético. Em escopo: revisão de `AndroidManifest.xml`, somente achados no nível do manifesto. Fora de escopo: todo o resto, porque não existe código-fonte, DEX nem APK para este fixture. Autorização: app próprio, escrito pelo mantenedor do repositório como fixture de teste (`scope.md`).

## Metodologia

- **Análise estática** (Fase 2): `android-manifest-auditor` rodou e produziu os seis registros. `android-ipc-ui-auditor` e `deeplink-clipboard-auditor` (subescopo DLK) foram recomendados em `target-profile.md`, mas nenhuma saída deles está no diretório do engajamento, então não há registro de que tenham rodado. Os outros dez especialistas foram ignorados (Apêndice C).
- **Análise dinâmica** (Fase 3): rodou de forma limitada. Um aparelho estava conectado, mas o pacote-alvo não estava instalado nele, então nenhum teste no nível do app foi possível. O comando dinâmico de cada achado foi tentado, e todos falharam por estado de instalação. Não existe prova de conceito dinâmica para nenhum achado.
- **Painel adversarial** (Fase 4): um promotor e três passes de céticos para AND-MAN-001 e AND-MAN-003 (`severity-rating.md` exige três passes para Alta). Os quatro candidatos nunca chegaram ao painel.
- **Severidade:** classificação de impacto (crítica a baixa), definida a partir do modelo de atacante, da sensibilidade do ativo e do raio de impacto. Somente o painel pode produzir Confirmado (`severity-rating.md`).
- **CVSS 3.1:** cada achado tem um vetor base. O score é calculado a partir dele por `scripts/cvss31.py`. Quando a faixa CVSS e a severidade do painel diferem em uma faixa ou mais, o achado mostra uma **Nota sobre a severidade**.

## Cobertura MASVS

| Controle MASVS | Cobertura | Achados |
|---|---|---|
| STORAGE | Parcial | AND-MAN-002, AND-MAN-004 |
| CRYPTO | Não testado | nenhum |
| AUTH | Parcial | AND-MAN-003 |
| NETWORK | Não testado | nenhum |
| PLATFORM | Parcial | AND-MAN-003, AND-MAN-004, AND-MAN-006 |
| CODE | Não testado | nenhum |
| RESILIENCE | Parcial | AND-MAN-001 |
| PRIVACY | Não testado | nenhum |

Parcial significa que o manifesto foi revisado para aquele controle e nenhuma implementação foi. Um controle marcado como Não testado, com o motivo no Apêndice C, não é um atestado de limpeza.

## Resumo dos achados

| # | Achado | Severidade | Status | Modelo de atacante | CVSS 3.1 | IDs de referência |
|---|---|---|---|---|---|---|
| 1 | AND-MAN-003: TransferMoneyActivity exportada com deep link BROWSABLE de esquema customizado e sem guarda de permissão | Alta | Potencial | remote | 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` | MAN-04, MAN-09 |
| 2 | AND-MAN-001: android:debuggable="true" definido explicitamente em application | Alta | Potencial | physical | 5.9 `CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | MAN-01 |
| 3 | AND-MAN-004: AccountProvider exportado sem permissão, sem path-permission e sem escopo de URI (Candidato, não revisado pelo painel) | Alta | Candidato | other-app | 7.7 `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | MAN-04, MAN-06 |
| 4 | AND-MAN-002: android:allowBackup="true" sem restrição de conteúdo de backup (Candidato, não revisado pelo painel) | Média | Candidato | physical | 4.6 `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | MAN-02 |
| 5 | AND-MAN-005: nenhum uses-sdk declarado (Candidato, não revisado pelo painel) | Baixa | Candidato | none | 0.0 `CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N` | MAN-12 |
| 6 | AND-MAN-006: inventário de componentes exportados, um mapa de superfície IPC e não uma vulnerabilidade (Candidato, não revisado pelo painel) | Info | Candidato | other-app | 0.0 `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | MAN-04 |

Ordem: Confirmados primeiro, depois Potenciais, depois Informativos. Dentro de cada status, a severidade vai de alta para baixa, depois o score CVSS, em ordem decrescente. Candidatos ficam sob Informativos. Falsos positivos: nenhum (Apêndice A).

## Achados confirmados

Nenhum identificado.

## Achados potenciais (detalhados)

### AND-MAN-003: TransferMoneyActivity exportada com deep link BROWSABLE de esquema customizado e sem guarda de permissão
- **Severidade:** Alta · **Status:** Potencial · **Modelo de atacante:** remote
- **CWE:** CWE-939 · **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` = 7.1 (Alta) · **MASVS:** MASVS-PLATFORM-1, MASVS-AUTH-1
- **Nota sobre a severidade:** nenhuma. A faixa CVSS (Alta) coincide com a severidade final (Alta).
- **Descrição:** `.ui.TransferMoneyActivity` é exportada e declara um filtro de intent BROWSABLE para `vulnbank://transfer`. Não tem `android:permission`, e o manifesto não define permissão customizada. Qualquer app, e qualquer link aberto em navegador, pode iniciá-la. O nome da classe sugere uma tela de movimentação de dinheiro, mas o código dela não está no registro.
- **Caminho de ataque:** Origem: um link `vulnbank://transfer` em uma página web, SMS ou chat, tocado por uma vítima que tem o app instalado. Um intent explícito de outro app é um subconjunto da mesma exposição (`extracted/AndroidManifest.xml:L24-33`) → propagação: a plataforma resolve o filtro BROWSABLE e entrega o intent sem checagem de permissão (sem `android:permission` na activity, sem elemento `<permission>` em lugar nenhum) → sink: `onCreate()`/`onNewIntent()` de `TransferMoneyActivity`. A implementação não está no registro, então o que ela faz ao receber o intent não foi verificado.
- **Reprodução (estática):**
  1. Abrir `extracted/AndroidManifest.xml`.
  2. Nas linhas L24-26, `<activity android:name=".ui.TransferMoneyActivity" android:exported="true">`. Sem atributo `android:permission`.
  3. Nas linhas L27-32, um filtro de intent: ação `VIEW`, categorias `DEFAULT` e `BROWSABLE`, `data android:scheme="vulnbank" android:host="transfer"`. Nenhum `pathPattern` ou `mimeType` restringe o filtro.
  4. Confirmar que não há elemento `<permission>` em lugar nenhum do arquivo de 41 linhas.
- **Reprodução (dinâmica):** `adb shell am start -a android.intent.action.VIEW -d "vulnbank://transfer" com.vulnbankdemo.app` retornou `Error: Activity not started, unable to resolve Intent` no dispositivo 84f7a024. O pacote não está instalado. A forma sem pacote também falhou, então nenhum app naquele dispositivo reclama o esquema. Isso mostra só o estado de instalação. Não testa a activity.
- **Evidências:** `extracted/AndroidManifest.xml:L24-33` (estática; SHA-256 não registrado) · `findings/dynamic-session-log.md` §3 (dinâmica, resultado negativo de estado de instalação) · `exploitation/AND-MAN-003.md` · `exploitation/AND-MAN-003.skeptic-3.md`
- **Veredito do painel adversarial:** A tese de alcançabilidade do promotor se sustenta. Três passes de céticos retornaram `stands`, e nenhum produziu refutação bem-evidenciada. O que foi tentado: (1) inflação do modelo de atacante: se "remote" exige secretamente um segundo app malicioso. Não exige, porque BROWSABLE permite que um navegador entregue o intent. (2) Sanitizador ausente: o manifesto inteiro foi procurado por `android:permission`, `<permission>`, restrições de `mimeType`/`pathPattern` e um segundo filtro. Nada foi encontrado. (3) App Links ou default de versão do SDK: não se aplicam, porque o esquema é customizado e `exported="true"` é explícito. (4) Comportamento padrão de deep link: um deep link sozinho não é o bug; o bug é o deep link combinado com nome sensível e sem guarda. (5) Um formulário de pré-preenchimento legítimo que mesmo assim exige reautenticação: plausível e não refutado. Essa é a lacuna em aberto, e é por ela que a classificação para em Potencial.
- **Correção:** Definir `android:exported="false"`, a menos que outros apps precisem alcançar esta tela. Se precisarem, proteger com permissão em nível de assinatura. Exigir reautenticação dentro do app antes de qualquer transferência, qualquer que seja o ponto de entrada. Não pegar valores nem destinatários da URI. Se um link precisar abrir a tela, usar App Link https verificado (`android:autoVerify="true"`) e manter a etapa de confirmação.
- **Critério de aceite:** Em build de release, nem `adb shell am start -a android.intent.action.VIEW -d "vulnbank://transfer"` nem um link tocado no navegador inicia uma transferência sem um prompt de autenticação, e `aapt2 dump xmltree` no APK de release mostra que a activity não é exportada ou tem guarda de permissão. Aguardando reteste.
- **Por que não está Confirmado:** faltam (a) código de implementação de `TransferMoneyActivity` mostrando que uma transferência roda sem etapa de reautenticação, ou (b) um teste dinâmico contra um build instalado deste manifesto no qual o link causa uma transferência. Também em aberto: se dados de caminho ou de query da URI chegam à lógica do app. O elemento `<data>` não tem filtro de caminho, então qualquer caminho casaria, mas se o código lê esses dados não foi estabelecido.
- **IDs de referência:** MAN-04, MAN-09

### AND-MAN-001: android:debuggable="true" definido explicitamente em application
- **Severidade:** Alta · **Status:** Potencial · **Modelo de atacante:** physical
- **CWE:** CWE-489 · **CVSS 3.1:** `CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 5.9 (Média) · **MASVS:** MASVS-RESILIENCE-2
- **Nota sobre a severidade:** A faixa CVSS é Média (5.9) e a severidade final do painel é Alta, a uma faixa de distância. O vetor codifica acesso físico (AV:P) e exigência de privilégio (PR:L): o atacante precisa primeiro de uma sessão ADB autorizada. O painel manteve Alta porque um `run-as` ou um attach JDWP bem-sucedido dá acesso total à sandbox do app e a qualquer checagem do lado do cliente, e porque os nomes dos componentes apontam para um ativo bancário, a exceção que `severity-rating.md` permite para achados de resiliência. O cético 3 sugeriu Média. O orquestrador não aplicou isso, e `final_severity` continua Alta.
- **Descrição:** O elemento `<application>` define `android:debuggable="true"` como valor literal e incondicional. Isso permite que um shell ADB use `run-as` sobre o diretório privado de dados do app, e que um debugger seja anexado ao processo do app.
- **Caminho de ataque:** Origem: um atacante com acesso físico e uma sessão ADB autorizada (depuração USB ativa, host autorizado) → propagação: o gerenciador de pacotes marca o app como depurável por causa de `extracted/AndroidManifest.xml:L10` (bloco L7-13), e nenhum override de release aparece no registro → sink: `run-as com.vulnbankdemo.app` dá leitura e escrita em `/data/data/com.vulnbankdemo.app/`, e um attach JDWP permite que um debugger leia e altere o estado do processo. O que fica armazenado ali é inferido pela finalidade aparente do app, não observado.
- **Reprodução (estática):**
  1. Abrir `extracted/AndroidManifest.xml`.
  2. Localizar `<application>` em L7-13. `android:debuggable="true"` está em L10.
  3. Procurar na árvore do engajamento por `tools:replace`, `tools:node`, um segundo manifesto ou um `build.gradle`. Nada encontrado, e não existe `build.gradle` na árvore.
- **Reprodução (dinâmica):** `adb shell run-as com.vulnbankdemo.app id` retornou `run-as: unknown package: com.vulnbankdemo.app` (saída 1) no dispositivo 84f7a024. O pacote não está instalado, então isso não diz nada sobre o comportamento de depuração.
- **Evidências:** `extracted/AndroidManifest.xml:L7-13` (estática; SHA-256 não registrado) · `findings/dynamic-session-log.md` §3 (dinâmica, resultado negativo de estado de instalação) · `exploitation/AND-MAN-001.md` · `exploitation/AND-MAN-001.skeptic-3.md`
- **Veredito do painel adversarial:** Três passes de céticos retornaram `stands`. O que foi tentado: (1) inflação do modelo de atacante: nenhum caminho de rede ou de segundo app alcança `run-as` ou JDWP, então `physical` foi mantido. (2) Override de build de release (o plugin Android Gradle força `debuggable=false` em release): não há `build.gradle` no registro para checar. Este é o único passo que poderia fechar o caso. (3) Diretivas de merge do manifesto e segundos manifestos: nenhum. (4) Default de targetSdk: `debuggable` não depende de versão. (5) Argumento de "artefato do decompilador": não se aplica, porque o arquivo é texto escrito à mão. (6) A precondição de ADB: real e declarada, e já considerada na classificação Potencial. A questão do override de release continua aberta, e é por ela que a classificação para em Potencial.
- **Correção:** Definir `android:debuggable="false"` (ou omitir) no build type de release. Manter `debuggable` como true somente no build de debug. Verificar o manifesto mesclado da variante de release.
- **Critério de aceite:** Em build de release instalado em um aparelho, `adb shell run-as com.vulnbankdemo.app id` falha porque o `run-as` informa que o pacote não é depurável, e o manifesto do APK de release não mostra `debuggable="true"`. A execução atual não conta: o pacote não estava instalado.
- **Por que não está Confirmado:** faltam um build instalado deste manifesto no qual `run-as` ou um attach JDWP tenha sucesso, ou uma configuração de release que mostre de forma conclusiva que o valor não é sobrescrito. Um build de release cujo manifesto mesclado defina `debuggable=false` fecharia o achado no sentido oposto. Também não verificado: o que a sandbox de fato guarda (tokens de sessão, dados de conta).
- **IDs de referência:** MAN-01

## Achados potenciais: o que os elevaria

Os dois itens acima apontam a evidência que os levaria a Confirmado. Em resumo: um build instalado deste manifesto, com o comportamento de transferência e da sandbox observado em aparelho, ou o código de implementação e a configuração de build de release que o painel pediu.

## Observações informativas e de hardening

Candidatos, não revisados pelo painel. Foram levantados por especialistas e nunca chegaram ao painel adversarial. A severidade é a primeira avaliação do especialista (`severity_initial`), não um veredito do painel.

- `AND-MAN-004` · AccountProvider exportado sem permissão, sem path-permission e sem escopo de URI · MAN-04, MAN-06 · Candidato, não revisado pelo painel. Alta na primeira avaliação, CVSS 7.7. O provider é exportado para qualquer app sem permissão, e o nome sugere dados de conta. Se implementa query/insert/update/delete, e o que retornam, não está no registro. · Definir `exported="false"`, ou proteger com `readPermission`/`writePermission` de assinatura e entradas de path-permission. Classificado P1 (regra 2) no plano.
- `AND-MAN-002` · android:allowBackup="true" sem restrição de conteúdo de backup · MAN-02 · Candidato, não revisado pelo painel. Média na primeira avaliação, CVSS 4.6. Se expõe tokens depende do que o app armazena, o que não está no registro. · Definir `allowBackup="false"`, ou adicionar um arquivo `fullBackupContent` ou `dataExtractionRules` que exclua arquivos de sessão e de conta.
- `AND-MAN-005` · Nenhum uses-sdk declarado · MAN-12 · Candidato, não revisado pelo painel. Baixa na primeira avaliação, CVSS 0.0. **Nota sobre a severidade:** a faixa CVSS nenhuma (0.0) e a severidade baixa diferem em uma faixa, então a nota é exigida. O vetor é AV:L/AC:H/PR:H sem impacto, e o achado é uma lacuna de configuração, não um sink alcançável. Defaults de plataforma dependentes de versão não podem ser verificados a partir deste manifesto. · Declarar `minSdkVersion` e `targetSdkVersion`, ou confirmá-los no `build.gradle`.
- `AND-MAN-006` · Inventário de componentes exportados (mapa de superfície IPC) · MAN-04 · Candidato, não revisado pelo painel. Um registro de inventário, não uma vulnerabilidade. `LoginActivity` é exportada como o ponto de entrada LAUNCHER, o que é esperado. CVSS 0.0. · Sem correção. Manter o inventário atualizado quando os componentes mudarem.

## Plano de remediação priorizado

Regra de prioridade aplicada, primeira que casa vence: P1 para Confirmado alto/crítico; P1 para qualquer achado alto/crítico cujo impacto seja credenciais, tokens, dados de conta, uma ação de pagamento ou transferência, ou uma sandbox que os guarda (inclui Potencial e candidato); P2 para outros Confirmados; P2 para Potencial alto/crítico não capturado acima; P2 para achados médios que expõem credenciais ou tokens; P3 para todo o resto. Dentro de uma prioridade, score CVSS em ordem decrescente. Empates em 0.0 são ordenados pelo ID do achado.

| Prioridade | Achado | Ação | Critério de aceite (reteste) |
|---|---|---|---|
| P1, corrigir agora (regra 2: dados de conta) | AND-MAN-004 AccountProvider exportado (CVSS 7.7, candidato) | Definir `android:exported="false"`, a menos que um consumidor externo precise dele. Se precisar, adicionar `readPermission`/`writePermission` protegidos por permissão de assinatura, e entradas `<path-permission>`. Revisar query/insert/update/delete quando a implementação for fornecida. | Em build de release, `adb shell content query --uri content://com.vulnbankdemo.app.provider` a partir do shell retorna negação de permissão ou nenhuma linha. Aguardando reteste: o pacote não estava instalado no aparelho de teste. |
| P1, corrigir agora (regra 2: ação de transferência) | AND-MAN-003 TransferMoneyActivity exportada com deep link BROWSABLE (CVSS 7.1, Potencial) | Definir `exported="false"`, ou proteger com permissão de assinatura. Exigir reautenticação dentro do app antes de qualquer transferência. Não pegar valores nem destinatários da URI. Se um link precisar abri-la, usar App Link verificado. | Em build de release, nem `adb shell am start -a android.intent.action.VIEW -d "vulnbank://transfer"` nem um link tocado no navegador inicia uma transferência sem prompt de autenticação. `aapt2 dump xmltree` no APK de release mostra que a activity não é exportada ou tem guarda de permissão. Aguardando reteste. |
| P2, próxima release (regra 4: Potencial alto, não capturado pela regra 2) | AND-MAN-001 debuggable="true" (CVSS 5.9, Potencial) | Definir `android:debuggable="false"` (ou omitir) no build type de release. Manter true somente em debug. | Em build de release instalado em um aparelho, `adb shell run-as com.vulnbankdemo.app id` falha porque o pacote não é depurável. O manifesto do APK de release não mostra `debuggable="true"`. Aguardando reteste. |
| P3, backlog (regra 6) | AND-MAN-002 allowBackup="true" (CVSS 4.6, candidato) | Definir `allowBackup="false"`, ou adicionar `fullBackupContent`/`dataExtractionRules` excluindo arquivos de sessão e de conta. | `aapt2 dump xmltree` no APK de release mostra `allowBackup="false"`, ou um arquivo de regras de backup que exclui arquivos de sessão. O backup do build de release não contém arquivos de sessão. Aguardando reteste. |
| P3, backlog (regra 6) | AND-MAN-005 Sem uses-sdk (CVSS 0.0, candidato) | Declarar `minSdkVersion` e `targetSdkVersion` no manifesto, ou confirmá-los no `build.gradle`. | `aapt2 dump badging` no APK de release imprime `sdkVersion` e `targetSdkVersion`. |
| P3, backlog (regra 6) | AND-MAN-006 Inventário de componentes (CVSS 0.0, candidato) | Sem correção de código. Manter o inventário atualizado conforme os componentes mudam. | A lista de componentes exportados no Apêndice B bate com `aapt2 dump xmltree` no APK de release. |

## Apêndice A: Falsos positivos e itens descartados

Nenhum identificado. Nenhum cético retornou refutação bem-evidenciada, então nenhum achado foi fechado como falso positivo. AND-MAN-001 e AND-MAN-003 foram mantidos como Potencial, não como Falso positivo. O `.ui.LoginActivity`, exportado como LAUNCHER, foi revisado em AND-MAN-006 e tratado como ponto de entrada esperado, não como achado.

## Apêndice B: Inventário da superfície de ataque

A partir de `target-profile.md`. O que não pode ser determinado pelo artefato está escrito como desconhecido.

- **Componentes exportados:** `.ui.LoginActivity` (Activity, exportada, MAIN/LAUNCHER, sem permissão; ponto de entrada esperado) · `.ui.TransferMoneyActivity` (Activity, exportada, VIEW/DEFAULT/BROWSABLE, `vulnbank://transfer`, sem permissão) · `.data.AccountProvider` (ContentProvider, exportado, authority `com.vulnbankdemo.app.provider`, sem permissão, sem path-permission). Nenhum elemento `<service>` ou `<receiver>` está declarado.
- **Esquemas de URL e App/Universal Links:** esquema customizado `vulnbank://transfer` (BROWSABLE). Sem App Links: sem `android:autoVerify`, sem filtro https, sem referência a `assetlinks.json`. Universal Links do iOS: não se aplica.
- **WebViews:** desconhecido. Não avaliável: não há código, e o manifesto não mostra uso de WebView.
- **Endpoints de rede:** desconhecido. Nenhuma string ou recurso foi fornecido. O único fato de rede visível é a permissão INTERNET.
- **Permissões e entitlements:** somente `android.permission.INTERNET`. Nenhum `<permission>` customizado. Entitlements do iOS: não se aplica.
- **SDKs de terceiros:** desconhecido. Nenhum arquivo de build, lockfile, biblioteca ou código nativo foi fornecido.
- **Versões:** `minSdkVersion` e `targetSdkVersion` desconhecidos (sem `<uses-sdk>`).

## Apêndice C: Metodologia e limitações

- **Especialistas executados:** `android-manifest-auditor` (`manifest-plist.md` §A, MAN-01..21; seis registros, AND-MAN-001 a AND-MAN-006). Recomendados, sem saída registrada: `android-ipc-ui-auditor` (`advanced-attacks.md` §A) e `deeplink-clipboard-auditor` (somente subescopo DLK de `clipboard-webview-oauth.md` §D). Não há registro de que tenham rodado, e não existem achados nem transcrições deles.
- **Especialistas ignorados, com motivo segundo `target-profile.md`:** `ios-plist-entitlements-auditor` e `ios-platform-attack-auditor` (artefato somente Android); `storage-crypto-auditor` (sem código de armazenamento ou criptografia); `taint-flow-analyst` (sem código-fonte nem DEX); `webview-security-auditor` (sem evidência de WebView e sem código); `oauth-oidc-auditor` (sem código ou configuração OAuth); `resilience-anti-tamper-auditor` (sem código e sem app em execução); `network-backend-auditor` (sem código de backend nem endpoints); `supply-chain-framework-auditor` (sem manifesto de dependências nem artefatos de SDK); `business-logic-auditor` (sem implementação de transferência).
- **Cobertura dinâmica:** a Fase 3 rodou de forma limitada. O dispositivo 84f7a024 estava conectado (Xiaomi M2101K6P, Android 11, SDK 30, build de usuário). O alvo nunca foi instalado: `pm list packages` (389 pacotes), `dumpsys package` e `run-as` confirmaram isso. O comando dinâmico de cada achado foi tentado uma vez, e nenhum conseguiu exercitar o app. Não tentado, porque não havia app em execução: hooking com Frida, captura de tráfego, teste de bypass de resiliência, teste de gate biométrico, diff de armazenamento e reteste. Outros pacotes no dispositivo compartilhado foram observados, mas não inspecionados. A tentativa de `adb backup` foi encerrada por timeout. Um toque de `KEYCODE_BACK` dispensou um diálogo de confirmação de backup, e o dispositivo voltou ao app em primeiro plano anterior. Nenhum dado foi lido, escrito ou exfiltrado. Isso é uma mudança de estado e está declarado aqui.
- **Ferramentas e versões:** adb 1.0.41 (platform-tools 35.0.2-12147458). apktool, jadx e aapt2 estão no host, mas não foram executados. `scripts/cvss31.py` e `scripts/decision_summary.py` (versões não registradas).
- **Fora de escopo segundo `scope.md`:** tudo exceto a revisão de `AndroidManifest.xml`: sem código-fonte, DEX, recursos, rede, backend ou comportamento do app no dispositivo.
- **O que mudou neste engajamento:** Agora existem três passes de céticos para AND-MAN-001 e AND-MAN-003 (`*.skeptic-3.md`). Os registros anteriores tinham dois. Cada decisão do orquestrador foi escrita depois de dois passes, e uma nota do terceiro passe foi acrescentada depois; as duas notas mantêm o status em Potencial. O cético 3 de AND-MAN-003 registrou que leu seções do arquivo de acusação que não deveria ler: as seções dos outros céticos e a decisão do orquestrador. O veredito dele cita apenas as próprias checagens, mas a independência dele é mais fraca do que um passe cego e limpo. O cético 3 de AND-MAN-001 propôs Média, que não foi aplicada.
- **Inconsistências encontradas na montagem:**
  - **O cético 3 de AND-MAN-003 leu além do que devia.** A transcrição dele diz que a primeira leitura do arquivo de acusação retornou o arquivo inteiro, incluindo as seções dos outros céticos e a decisão do orquestrador, embora as instruções limitassem a leitura às seções do promotor. Ele diz que não adotou o veredito a partir dessas seções e que o formou a partir das próprias checagens contra o manifesto. A independência dele é, portanto, mais fraca do que um passe cego e limpo. Este relatório conta esse passe como o terceiro de AND-MAN-003, com essa ressalva.
  - **Momento da decisão.** As decisões do orquestrador para AND-MAN-001 e AND-MAN-003 foram escritas depois de dois passes de céticos. A nota do terceiro passe foi acrescentada depois, e ambas dizem que o status continuou Potencial. O registro não mostra uma reaplicação separada da regra para o terceiro passe.
  - **Divergência de severidade.** O cético 3 em AND-MAN-001 propôs Média. Não foi aplicado e está declarado na nota sobre a severidade.
  - **Contagens de linhas.** O caso do promotor em AND-MAN-001 descreve um manifesto de 42 linhas. Os céticos 1 e 3 descrevem 41 linhas. Os números de linha citados (L7-13, L10, L24-33) batem em todas as transcrições. Não consegui verificar a contagem sem shell.
  - **Arquivo de backup ausente.** A transcrição do cético 1 de AND-MAN-001 lista `findings/findings.jsonl.bak` no diretório. Ele não está presente nesta cópia de trabalho e não foi usado.
  - **Linhas truncadas no registro.** As linhas de `findings.jsonl` foram truncadas em 2000 caracteres ao serem lidas. Os campos de decisão vêm de `decision-summary.json`, como exigido. Os campos visíveis (`cwe`, `cvss_vector`, `attacker_model`) batem com `decision-summary.json` nos seis registros. `status` e `severity_initial` na parte truncada não puderam ser conferidos contra o registro completo.
  - **Deduplicação.** Nenhuma fusão. Os seis registros vêm de um só especialista. AND-MAN-006 se sobrepõe a AND-MAN-003 e AND-MAN-004 por referência e componente, mas é um registro de inventário, não um problema. Foi mantido como candidato e não é contado como vulnerabilidade distinta além dos seis registros.
  - **Posição de AND-MAN-004.** Está como Alta na primeira avaliação, mas aparece sob Informativos porque o status é `candidate`, como as regras exigem. Está classificado como P1 no plano porque é Alta e expõe dados de conta.
  - **Severidade de candidatos.** Candidatos não têm `final_severity`, então a nota de severidade de AND-MAN-005 usa `severity_initial` (baixa) contra CVSS nenhum. A regra não diz qual valor usar para candidatos. `info` foi tratado como a mesma faixa de nenhum para AND-MAN-006, então nenhuma nota foi acrescentada ali.
  - **Ambiguidade de prioridade (AND-MAN-001 e AND-MAN-004).** A regra 2 depende de o impacto ser credenciais, tokens, dados de conta, ou uma sandbox que os guarda. Para AND-MAN-004, o sink do especialista nomeia dados de conta ou financeiros, então a regra 2 foi aplicada (P1), com base na inferência do especialista. Para AND-MAN-001, o sink nomeia apenas a sandbox do app, e nada no registro mostra que ela guarda credenciais ou tokens. A regra 2 não foi aplicada, e a regra 4 foi (P2). As regras não resolvem como tratar um sink inferido a partir de nome de classe. As duas decisões se apoiam no mesmo tipo de inferência, então um leitor pode razoavelmente ranquear AND-MAN-001 mais alto.
  - **Empates e ordem.** Os achados com CVSS 0.0 são ordenados pelo ID, porque o template não define desempate.
  - **Rótulos fora de `report-i18n.md`.** "Principais riscos", "Contagens" e os nomes das faixas CVSS (nenhuma, baixa, média, alta, crítica). Foram fornecidos nos dois idiomas com redação correspondente.
  - **Saída de Fase 2 ausente.** Não existe saída de `android-ipc-ui-auditor` nem de `deeplink-clipboard-auditor` (ver Especialistas executados acima).
  - **Lacunas de metadados.** Versão/build do app e SHA-256 do artefato são desconhecidos. `target-profile.md` não registra nenhum dos dois.
  - **Rodapé do template.** O link do template para um repositório externo foi removido, para cumprir a regra de nenhum link externo nesta execução.
  - **Datas.** O escopo é datado de 2026-10-08 e a sessão dinâmica de 2026-10-09. A data do relatório é 2026-11-11.

## Apêndice D: Glossário

| Termo | Significado |
|---|---|
| Confirmado | Explorável pelo modelo de atacante declarado nesta build, com evidência dinâmica ou estática inequívoca, e as tentativas de refutação do painel falharam. |
| Potencial | Plausível e vale corrigir, mas o ciclo não pôde ser fechado. O relatório diz o que o confirmaria. |
| Informativo | Observação de boa prática ou hardening sem modelo de atacante crível neste contexto. |
| Falso positivo | O painel mostrou que o caminho está fechado ou inalcançável. Mantido no Apêndice A para mostrar o que foi verificado. |
| Candidato | Levantado por um especialista e ainda não revisado pelo painel. Não é veredito. |
| Modelo de atacante | Quem pode executar o ataque: remoto, outro app no dispositivo, acesso físico ou dispositivo com root. |
| CVSS 3.1 | Score base padrão calculado a partir do vetor. Descreve ataque e impacto; não decide o status. |
| Nota sobre a severidade | Explicação exibida quando a faixa CVSS e a severidade do painel diferem em uma faixa ou mais. |
| MASVS | Padrão de verificação de segurança do OWASP Mobile, o conjunto de controles usado para organizar este relatório. |
| CWE | Common Weakness Enumeration, a classe de fraqueza da causa raiz. |
| Refutação bem-evidenciada | Refutação de um cético que cita um fato específico e verificável que quebra um passo do caminho do promotor. |
| Critério de aceite | A verificação observável que prova que a correção funciona no reteste. |

## Apêndice E: Auditoria anterior

Não se aplica. Nenhum relatório ou arquivo de achados anterior foi fornecido. Ver Apêndice C para a referência a `findings.jsonl.bak`, que não está presente nesta cópia de trabalho.
