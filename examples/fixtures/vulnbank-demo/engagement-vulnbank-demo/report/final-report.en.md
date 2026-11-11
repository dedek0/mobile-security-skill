# Mobile Application Security Assessment: VulnBank Demo (build unknown)

> Confidential: contains unpatched vulnerability details

| | |
|---|---|
| **Platform(s)** | Android only. No iOS artifacts were provided. |
| **Framework** | Native Android (Java/Kotlin), assumed from class names. Not verified: no DEX or source was provided. |
| **Artifact SHA-256** | `unknown` (not recorded in `target-profile.md`) |
| **Assessment window** | 2026-10-08 to 2026-10-09 (`scope.md` dated 2026-10-08; dynamic session 2026-10-09) |
| **Authorization and scope** | Own app. A synthetic test fixture written by the repo maintainer (see `scope.md`). |
| **Tools and versions** | adb 1.0.41 (platform-tools 35.0.2-12147458). apktool, jadx and aapt2 are present on the host but were not run, because no APK exists. Manual review of `AndroidManifest.xml`. `scripts/cvss31.py` (version not recorded). |

## Executive summary

No finding has reached Confirmed; two are Potential and rated High, and four are candidates the panel did not review. The worst is AND-MAN-003, an exported, browsable deep link into a transfer screen with no permission guard, which could not be closed because the app was never installed on the test device and no implementation code was supplied. Fix the manifest flags before any release build, and add a permission guard and an in-app re-authentication step to the transfer path.

**Counts** (severity is `final_severity` for panel-reviewed findings and `severity_initial` for candidates):
- By severity: Critical 0 · High 3 · Medium 1 · Low 1 · Info 1
- By status: Confirmed 0 · Potential 2 · Informational 0 · False positive 0 · Candidate 4
- Distinct issues: 6 (no merges, see Appendix C)

**Top risks:** AND-MAN-003 (Potential, High, CVSS 7.1) · AND-MAN-001 (Potential, High, CVSS 5.9) · AND-MAN-004 (Candidate, High on first call, CVSS 7.7, not panel-reviewed)

## Scope and authorization

Target: VulnBank Demo (`com.vulnbankdemo.app`), a synthetic manifest fixture. In scope: `AndroidManifest.xml` review, manifest-level findings only. Out of scope: everything else, because no source, DEX or APK exists for this fixture. Authorization: own app, written by the repo maintainer as a test fixture (`scope.md`).

## Methodology

- **Static analysis** (Phase 2): `android-manifest-auditor` ran and produced all six records. `android-ipc-ui-auditor` and `deeplink-clipboard-auditor` (DLK sub-scope) were recommended in `target-profile.md`, but no output from them is in the engagement directory, so whether they ran is not recorded. The other ten specialists were skipped (Appendix C).
- **Dynamic analysis** (Phase 3): ran in limited form. A device was connected, but the target package was not installed on it, so no app-level test was possible. Each finding's own dynamic command was attempted, and all failed on install state. No dynamic proof-of-concept exists for any finding.
- **Adversarial panel** (Phase 4): a prosecutor and three skeptic passes for AND-MAN-001 and AND-MAN-003 (`severity-rating.md` requires three passes for High). The four candidates never reached the panel.
- **Severity:** impact rating (critical to low), set from attacker model, asset sensitivity and blast radius. Only the panel can produce Confirmed (`severity-rating.md`).
- **CVSS 3.1:** every finding carries a base vector. The score is computed from it by `scripts/cvss31.py`. Where the CVSS band and the panel's severity differ by one band or more, the finding shows a **Severity note**.

## MASVS coverage

| MASVS control | Coverage | Findings |
|---|---|---|
| STORAGE | Partial | AND-MAN-002, AND-MAN-004 |
| CRYPTO | Not tested | none |
| AUTH | Partial | AND-MAN-003 |
| NETWORK | Not tested | none |
| PLATFORM | Partial | AND-MAN-003, AND-MAN-004, AND-MAN-006 |
| CODE | Not tested | none |
| RESILIENCE | Partial | AND-MAN-001 |
| PRIVACY | Not tested | none |

Partial means the manifest was reviewed for that control and no implementation was. A control marked Not tested, with its reason in Appendix C, is not a clean bill of health.

## Findings summary

| # | Finding | Severity | Status | Attacker model | CVSS 3.1 | Ref IDs |
|---|---|---|---|---|---|---|
| 1 | AND-MAN-003: TransferMoneyActivity exported with BROWSABLE custom-scheme deep link and no permission guard | High | Potential | remote | 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` | MAN-04, MAN-09 |
| 2 | AND-MAN-001: android:debuggable="true" set explicitly on application | High | Potential | physical | 5.9 `CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | MAN-01 |
| 3 | AND-MAN-004: AccountProvider exported with no permission, no path-permission, no URI scoping (Candidate, not panel-reviewed) | High | Candidate | other-app | 7.7 `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | MAN-04, MAN-06 |
| 4 | AND-MAN-002: android:allowBackup="true" with no backup-content restriction (Candidate, not panel-reviewed) | Medium | Candidate | physical | 4.6 `CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | MAN-02 |
| 5 | AND-MAN-005: No uses-sdk declared (Candidate, not panel-reviewed) | Low | Candidate | none | 0.0 `CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N` | MAN-12 |
| 6 | AND-MAN-006: Exported component inventory, an IPC surface map rather than a vulnerability (Candidate, not panel-reviewed) | Info | Candidate | other-app | 0.0 `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | MAN-04 |

Order: Confirmed first, then Potential, then Informational. Inside each status, severity runs from high to low, then CVSS score, descending. Candidates sit under Informational. False positives: none (Appendix A).

## Confirmed findings

None identified.

## Potential findings (detailed)

### AND-MAN-003: TransferMoneyActivity exported with BROWSABLE custom-scheme deep link and no permission guard
- **Severity:** High · **Status:** Potential · **Attacker model:** remote
- **CWE:** CWE-939 · **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N` = 7.1 (High) · **MASVS:** MASVS-PLATFORM-1, MASVS-AUTH-1
- **Severity note:** none. The CVSS band (High) matches the final severity (High).
- **Description:** `.ui.TransferMoneyActivity` is exported and declares a BROWSABLE intent filter for `vulnbank://transfer`. It has no `android:permission`, and the manifest defines no custom permission. Any app, and any link opened in a browser, can start it. The class name suggests a money-movement screen, but its code is not in the record.
- **Attack path:** Source: a `vulnbank://transfer` link in a web page, SMS or chat, tapped by a victim who has the app installed. An explicit intent from another app is a subset of the same exposure (`extracted/AndroidManifest.xml:L24-33`) → propagation: the platform resolves the BROWSABLE filter and delivers the intent with no permission check (no `android:permission` on the activity, no `<permission>` element anywhere) → sink: `TransferMoneyActivity` `onCreate()`/`onNewIntent()`. The implementation is not in the record, so what it does on receipt is unverified.
- **Reproduction (static):**
  1. Open `extracted/AndroidManifest.xml`.
  2. At L24-26, `<activity android:name=".ui.TransferMoneyActivity" android:exported="true">`. No `android:permission` attribute.
  3. At L27-32, one intent filter: action `VIEW`, categories `DEFAULT` and `BROWSABLE`, `data android:scheme="vulnbank" android:host="transfer"`. No `pathPattern` or `mimeType` restricts it.
  4. Confirm there is no `<permission>` element anywhere in the 41-line file.
- **Reproduction (dynamic):** `adb shell am start -a android.intent.action.VIEW -d "vulnbank://transfer" com.vulnbankdemo.app` returned `Error: Activity not started, unable to resolve Intent` on device 84f7a024. The package is not installed. A package-less form also failed, so no app on that device claims the scheme. This shows the install state only. It does not test the activity.
- **Evidence:** `extracted/AndroidManifest.xml:L24-33` (static; SHA-256 not recorded) · `findings/dynamic-session-log.md` §3 (dynamic, negative install-state result) · `exploitation/AND-MAN-003.md` · `exploitation/AND-MAN-003.skeptic-3.md`
- **Exploitation panel verdict:** The prosecutor's reachability case stands. Three skeptic passes returned `stands`, and none produced a well-evidenced refutation. What was tried: (1) attacker-model inflation: whether "remote" secretly needs a second malicious app. It does not, because BROWSABLE lets a browser deliver the intent. (2) Missing sanitizer: the whole manifest was searched for `android:permission`, `<permission>`, `mimeType`/`pathPattern` restrictions and a second filter. None found. (3) App Links or SDK-version default: not applicable, because the scheme is custom and `exported="true"` is explicit. (4) Standard deep-link behavior: a deep link alone is not the bug; the bug is the deep link combined with a sensitive name and no guard. (5) A legitimate pre-fill form that still demands re-authentication: plausible and not disproven. That is the open gap, and it is why the rating stops at Potential.
- **Remediation:** Set `android:exported="false"` unless other apps must reach this screen. If they must, guard it with a signature-level permission. Require in-app re-authentication before any transfer, whatever the entry point. Do not take amounts or recipients from the URI. If a link must open the screen, use a verified https App Link (`android:autoVerify="true"`) and keep the confirmation step.
- **Acceptance criterion:** On a release build, neither `adb shell am start -a android.intent.action.VIEW -d "vulnbank://transfer"` nor a browser-tapped link starts a transfer without an authentication prompt, and `aapt2 dump xmltree` on the release APK shows the activity is not exported or carries a permission guard. Pending retest.
- **Why it is not Confirmed:** needed are (a) implementation code for `TransferMoneyActivity` showing that a transfer runs with no re-authentication step, or (b) a dynamic test against an installed build of this manifest in which the link causes a transfer. Also open: whether path or query data from the URI reaches application logic. The `<data>` element has no path filter, so any path would match, but whether the code reads it is not established.
- **Ref IDs:** MAN-04, MAN-09

### AND-MAN-001: android:debuggable="true" set explicitly on application
- **Severity:** High · **Status:** Potential · **Attacker model:** physical
- **CWE:** CWE-489 · **CVSS 3.1:** `CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 5.9 (Medium) · **MASVS:** MASVS-RESILIENCE-2
- **Severity note:** The CVSS band is Medium (5.9) and the panel's final severity is High, one band apart. The vector encodes physical access (AV:P) and a privilege requirement (PR:L): the attacker first needs an authorized ADB session. The panel kept High because a successful `run-as` or JDWP attach gives full access to the app sandbox and to any client-side check, and because the component names point to a banking asset, which is the exception `severity-rating.md` allows for resilience findings. Skeptic-3 suggested Medium. The orchestrator did not apply that, and `final_severity` remains High.
- **Description:** The `<application>` element sets `android:debuggable="true"` as a literal, unconditional value. That lets an ADB shell use `run-as` on the app's private data directory, and lets a debugger attach to the app's process.
- **Attack path:** Source: an attacker with physical access and an authorized ADB session (USB debugging enabled, host authorized) → propagation: the package manager marks the app as debuggable because of `extracted/AndroidManifest.xml:L10` (block L7-13), and no release override is visible in the record → sink: `run-as com.vulnbankdemo.app` gives read/write access to `/data/data/com.vulnbankdemo.app/`, and a JDWP attach lets a debugger read and change the process's state. What is stored there is inferred from the app's apparent purpose, not observed.
- **Reproduction (static):**
  1. Open `extracted/AndroidManifest.xml`.
  2. Locate `<application>` at L7-13. `android:debuggable="true"` is on L10.
  3. Search the engagement tree for `tools:replace`, `tools:node`, a second manifest, or a `build.gradle`. None found, and no `build.gradle` exists in the tree.
- **Reproduction (dynamic):** `adb shell run-as com.vulnbankdemo.app id` returned `run-as: unknown package: com.vulnbankdemo.app` (exit 1) on device 84f7a024. The package is not installed, so this says nothing about debuggable behavior.
- **Evidence:** `extracted/AndroidManifest.xml:L7-13` (static; SHA-256 not recorded) · `findings/dynamic-session-log.md` §3 (dynamic, negative install-state result) · `exploitation/AND-MAN-001.md` · `exploitation/AND-MAN-001.skeptic-3.md`
- **Exploitation panel verdict:** Three skeptic passes returned `stands`. What was tried: (1) attacker-model inflation: no network or second-app path reaches `run-as` or JDWP, so `physical` was kept. (2) Release-build override (the Android Gradle plugin forces `debuggable=false` for release): no `build.gradle` is in the record to check. This is the one step that could close the case. (3) Manifest-merger directives and second manifests: none. (4) targetSdk default: `debuggable` is not version-gated. (5) "Decompiler artifact" argument: not applicable, because the file is hand-written text. (6) The ADB precondition: real and disclosed, and already priced into the Potential rating. The release-override question stays open, and that is why the rating stops at Potential.
- **Remediation:** Set `android:debuggable="false"` (or omit it) for the release build type. Keep `debuggable` true only in the debug build type. Verify the merged manifest of the release variant.
- **Acceptance criterion:** On a release build installed on a device, `adb shell run-as com.vulnbankdemo.app id` fails because `run-as` reports the package is not debuggable, and the release APK manifest shows no `debuggable="true"`. The current run does not count: the package was not installed.
- **Why it is not Confirmed:** needed are an installed build of this manifest on which `run-as` or a JDWP attach succeeds, or a release configuration that conclusively shows the value is not overridden. A release build whose merged manifest sets `debuggable=false` would close the finding instead. Also unverified: what the sandbox actually holds (session tokens, account data).
- **Ref IDs:** MAN-01

## Potential findings: what would upgrade them

The two items above name the evidence that would upgrade each to Confirmed. In short: an installed build of this manifest, with the transfer and sandbox behavior observed on a device, or the implementation code and release build configuration that the panel asked for.

## Informational and hardening observations

Candidate, not panel-reviewed. These were raised by specialists and never reached the exploitation panel. Their severity is the specialist's first call (`severity_initial`), not a panel verdict.

- `AND-MAN-004` · AccountProvider exported with no permission, no path-permission, no URI scoping · MAN-04, MAN-06 · Candidate, not panel-reviewed. High on first call, CVSS 7.7. The provider is exported to any app with no permission, and its name implies account data. Whether it implements query/insert/update/delete, and what they return, is not in the record. · Set `exported="false"`, or guard it with a signature `readPermission`/`writePermission` and path-permission entries. Ranked P1 (rule 2) in the plan.
- `AND-MAN-002` · android:allowBackup="true" with no backup-content restriction · MAN-02 · Candidate, not panel-reviewed. Medium on first call, CVSS 4.6. Whether it exposes tokens depends on what the app stores, which is not in the record. · Set `allowBackup="false"`, or add a `fullBackupContent` or `dataExtractionRules` file that excludes session and account files.
- `AND-MAN-005` · No uses-sdk declared · MAN-12 · Candidate, not panel-reviewed. Low on first call, CVSS 0.0. **Severity note:** CVSS band none (0.0) and severity low differ by one band, so the note is required. The vector is AV:L/AC:H/PR:H with no impact, and the finding is a configuration gap, not a reachable sink. Version-gated platform defaults cannot be checked from this manifest. · Declare `minSdkVersion` and `targetSdkVersion`, or confirm them in `build.gradle`.
- `AND-MAN-006` · Exported component inventory (IPC surface map) · MAN-04 · Candidate, not panel-reviewed. An inventory record, not a vulnerability. `LoginActivity` is exported as the LAUNCHER entry point, which is expected. CVSS 0.0. · No fix. Keep the inventory current when components change.

## Prioritized remediation plan

Priority rule applied, first match wins: P1 for Confirmed high/critical; P1 for any high/critical finding whose impact is credentials, tokens, account data, a payment or transfer action, or a sandbox holding them (Potential and candidate included); P2 for other Confirmed; P2 for Potential high/critical not caught above; P2 for medium findings exposing credentials or tokens; P3 for everything else. Within a priority, CVSS score descending. Ties at 0.0 are ordered by finding ID.

| Priority | Finding | Action | Acceptance criterion (retest) |
|---|---|---|---|
| P1, fix now (rule 2: account data in a sandbox) | AND-MAN-004 AccountProvider exported (CVSS 7.7, candidate) | Set `android:exported="false"` unless an external consumer needs it. If one does, add `readPermission`/`writePermission` guarded by a signature permission, and `<path-permission>` entries. Review query/insert/update/delete once the implementation is supplied. | On a release build, `adb shell content query --uri content://com.vulnbankdemo.app.provider` from the shell returns a permission denial or no rows. Pending retest: the package was not installed on the test device. |
| P1, fix now (rule 2: transfer action) | AND-MAN-003 TransferMoneyActivity exported with BROWSABLE deep link (CVSS 7.1, Potential) | Set `exported="false"`, or guard it with a signature permission. Require in-app re-authentication before any transfer. Take no amounts or recipients from the URI. If a link must open it, use a verified App Link. | On a release build, neither `adb shell am start -a android.intent.action.VIEW -d "vulnbank://transfer"` nor a browser-tapped link starts a transfer without an authentication prompt. `aapt2 dump xmltree` on the release APK shows the activity is not exported or is permission-guarded. Pending retest. |
| P2, next release (rule 4: Potential high, not caught by rule 2) | AND-MAN-001 debuggable="true" (CVSS 5.9, Potential) | Set `android:debuggable="false"` (or omit it) in the release build type. Keep it true only in debug. | On a release build installed on a device, `adb shell run-as com.vulnbankdemo.app id` fails because the package is not debuggable. The release APK manifest shows no `debuggable="true"`. Pending retest. |
| P3, backlog (rule 6) | AND-MAN-002 allowBackup="true" (CVSS 4.6, candidate) | Set `allowBackup="false"`, or add `fullBackupContent`/`dataExtractionRules` excluding session and account files. | `aapt2 dump xmltree` on the release APK shows `allowBackup="false"`, or a backup-rules file that excludes session files. Backup of the release build contains no session files. Pending retest. |
| P3, backlog (rule 6) | AND-MAN-005 No uses-sdk (CVSS 0.0, candidate) | Declare `minSdkVersion` and `targetSdkVersion` in the manifest, or confirm them in `build.gradle`. | `aapt2 dump badging` on the release APK prints both `sdkVersion` and `targetSdkVersion`. |
| P3, backlog (rule 6) | AND-MAN-006 Component inventory (CVSS 0.0, candidate) | No code fix. Keep the inventory current as components change. | The exported-component list in Appendix B matches `aapt2 dump xmltree` on the release APK. |

## Appendix A: False positives and ruled out

None identified. No skeptic returned a well-evidenced refutation, so no finding was closed as a false positive. AND-MAN-001 and AND-MAN-003 were both kept at Potential, not False Positive. The exported LAUNCHER activity `.ui.LoginActivity` was reviewed in AND-MAN-006 and treated as an expected entry point, not a finding.

## Appendix B: Attack surface inventory

From `target-profile.md`. Anything not determinable from the artifact is written as unknown.

- **Exported components:** `.ui.LoginActivity` (Activity, exported, MAIN/LAUNCHER, no permission; expected entry point) · `.ui.TransferMoneyActivity` (Activity, exported, VIEW/DEFAULT/BROWSABLE, `vulnbank://transfer`, no permission) · `.data.AccountProvider` (ContentProvider, exported, authority `com.vulnbankdemo.app.provider`, no permission, no path-permission). No `<service>` or `<receiver>` elements are declared.
- **URL schemes and App/Universal Links:** custom scheme `vulnbank://transfer` (BROWSABLE). No App Links: no `android:autoVerify`, no https filter, no `assetlinks.json` reference. iOS Universal Links: not applicable.
- **WebViews:** unknown. Not assessable: no code, and the manifest does not show WebView usage.
- **Network endpoints:** unknown. No strings or resources were provided. The only visible network fact is the INTERNET permission.
- **Permissions and entitlements:** `android.permission.INTERNET` only. No custom `<permission>`. iOS entitlements: not applicable.
- **Third-party SDKs:** unknown. No build file, lockfile, library or native code was provided.
- **Versions:** `minSdkVersion` and `targetSdkVersion` unknown (no `<uses-sdk>`).

## Appendix C: Methodology and limitations

- **Specialists run:** `android-manifest-auditor` (`manifest-plist.md` §A, MAN-01..21; six records, AND-MAN-001 to AND-MAN-006). Recommended, with no output recorded: `android-ipc-ui-auditor` (`advanced-attacks.md` §A) and `deeplink-clipboard-auditor` (DLK sub-scope of `clipboard-webview-oauth.md` §D only). Whether they ran is not recorded, and no findings or transcripts from them exist.
- **Specialists skipped, with reasons from `target-profile.md`:** `ios-plist-entitlements-auditor` and `ios-platform-attack-auditor` (Android-only artifact); `storage-crypto-auditor` (no storage or crypto code); `taint-flow-analyst` (no source or DEX); `webview-security-auditor` (no WebView evidence and no code); `oauth-oidc-auditor` (no OAuth code or configuration); `resilience-anti-tamper-auditor` (no code and no running app); `network-backend-auditor` (no backend code or endpoints); `supply-chain-framework-auditor` (no dependency manifest or SDK artifacts); `business-logic-auditor` (no transfer implementation).
- **Dynamic coverage:** Phase 3 ran in limited form. Device 84f7a024 was connected (Xiaomi M2101K6P, Android 11, SDK 30, user build). The target was never installed: `pm list packages` (389 packages), `dumpsys package` and `run-as` all confirmed it. Each finding's own dynamic command was attempted once, and none could exercise the app. Not attempted, because there was no running app: Frida hooking, traffic capture, resilience bypass, biometric-gate testing, storage diffing, and retest. Other packages on the shared device were observed but not inspected. The `adb backup` attempt was killed by timeout. One `KEYCODE_BACK` press dismissed a backup confirmation dialog, and the device returned to its previous foreground app. No data was read, written or exfiltrated. This is a state change and is disclosed here.
- **Tools and versions:** adb 1.0.41 (platform-tools 35.0.2-12147458). apktool, jadx and aapt2 are on the host but were not run. `scripts/cvss31.py` and `scripts/decision_summary.py` (versions not recorded).
- **Out of scope per `scope.md`:** everything except the `AndroidManifest.xml` review: no source, DEX, resources, network, backend, or device-side app behavior.
- **What changed in this engagement:** Three skeptic passes now exist for AND-MAN-001 and AND-MAN-003 (`*.skeptic-3.md`). Earlier records had two. Each orchestrator decision was written after two passes, and a third-pass note was appended afterward; both notes keep the status at Potential. The skeptic-3 pass for AND-MAN-003 recorded that it read sections of the accusation file it was not meant to read: the other skeptics' sections and the orchestrator decision. Its verdict cites only its own checks, but its independence is weaker than a clean blind pass. Skeptic-3 for AND-MAN-001 proposed Medium, which was not applied.
- **Inconsistencies found during assembly:**
  - **Skeptic-3 on AND-MAN-003 read beyond its brief.** Its transcript states that its first read of the accusation file returned the whole file, including the other skeptics' sections and the orchestrator decision, although its instructions limited it to the prosecutor sections. It says it did not adopt its verdict from those sections and formed it from its own checks against the manifest. Its independence is therefore weaker than a clean blind pass. This report counts it as the third pass for AND-MAN-003, with that caveat.
  - **Decision timing.** The AND-MAN-001 and AND-MAN-003 orchestrator decisions were written after two skeptic passes. The third-pass note was appended afterward, and both notes say the status stayed Potential. The record does not show a separate re-application of the rule for the third pass.
  - **Severity disagreement.** Skeptic-3 on AND-MAN-001 proposed Medium. It was not applied and is disclosed in the severity note.
  - **Line counts.** The prosecutor's case on AND-MAN-001 describes a 42-line manifest. Skeptic-1 and skeptic-3 describe 41 lines. The cited line numbers (L7-13, L10, L24-33) agree across all transcripts. I could not verify the count without a shell.
  - **Missing backup file.** The skeptic-1 transcript for AND-MAN-001 lists `findings/findings.jsonl.bak` in the directory. It is not present in this working copy and was not used.
  - **Priority ambiguity (AND-MAN-001 and AND-MAN-004).** Rule 2 turns on impact being credentials, tokens, account data, or a sandbox that holds them. For AND-MAN-004, the specialist's sink names account or financial data, so rule 2 was applied (P1), on the specialist's inference. For AND-MAN-001, the sink names only the app sandbox, and nothing in the record shows that it holds credentials or tokens. Rule 2 was therefore not applied and rule 4 was (P2). The rules do not settle how to treat a sink that is inferred from a class name. Both calls rest on the same kind of inference, so a reader may reasonably rank AND-MAN-001 higher.
  - **Truncated record lines.** The `findings.jsonl` lines were truncated at 2000 characters when read. Decision fields come from `decision-summary.json`, as required. The visible fields (`cwe`, `cvss_vector`, `attacker_model`) match `decision-summary.json` for all six records. `status` and `severity_initial` in the truncated part could not be checked against the full record.
  - **Dedup.** No merges. All six records come from one specialist. AND-MAN-006 overlaps AND-MAN-003 and AND-MAN-004 by ref and component, but it is an inventory record, not an issue. It is kept as a candidate and is not counted as a distinct vulnerability beyond the six records.
  - **AND-MAN-004 placement.** It is High on first call, but it sits under Informational because its status is `candidate`, as the rules require. It is ranked P1 in the plan because it is High and exposes account data.
  - **Candidate severity notes.** Candidates have no `final_severity`, so the severity note for AND-MAN-005 uses `severity_initial` (low) against CVSS none. The rule does not say which value to use for candidates. `info` is treated as the same band as none for AND-MAN-006, so no note is added there.
  - **Priority ambiguity.** AND-MAN-002 is Medium. Whether backup exposure of session data counts as exposing tokens (rule 5) is not established by the record, which does not show that tokens are stored. Rule 6 (P3) was applied. Ties at CVSS 0.0 are ordered by finding ID; the template gives no tie-break.
  - **Labels not in `report-i18n.md`.** "Top risks", "Counts", and the CVSS band names (none, low, medium, high, critical). They are supplied in both languages with matching wording.
  - **Tie-break.** Findings at CVSS 0.0 are ordered by finding ID, because the template gives no tie-break.
  - **Missing Phase 2 output.** No output from `android-ipc-ui-auditor` or `deeplink-clipboard-auditor` exists (see Specialists run above).
  - **Metadata gaps.** App version/build and artifact SHA-256 are unknown. `target-profile.md` records neither.
  - **Template footer.** The template's link to an external repository was removed, to meet the no-external-link rule for this run.
  - **Dates.** The scope is dated 2026-10-08 and the dynamic session 2026-10-09. The report date is 2026-11-11.

## Appendix D: Glossary

| Term | Meaning |
|---|---|
| Confirmed | Exploitable by the stated attacker model in this build, with dynamic or unambiguous static evidence, and the panel's refutation attempts failed. |
| Potential | Plausible and worth fixing, but the loop could not be closed. The report states what would upgrade it. |
| Informational | Best-practice or hardening observation without a credible attacker model in this context. |
| False positive | The panel's refutation showed the path is closed or unreachable. Kept in Appendix A to show what was checked. |
| Candidate | Raised by a specialist and not yet reviewed by the panel. Not a verdict. |
| Attacker model | Who can perform the attack: remote, another app on the device, physical access, or a rooted device. |
| CVSS 3.1 | Standard base score computed from the vector. It describes the attack and impact; it does not decide the status. |
| Severity note | Explanation shown when the CVSS band and the panel's severity differ by one band or more. |
| MASVS | OWASP Mobile Application Security Verification Standard, the control set this report is organized by. |
| CWE | Common Weakness Enumeration, the weakness class of the root cause. |
| Well-evidenced refutation | A skeptic's refutation that cites a specific, checkable fact breaking a step of the prosecutor's path. |
| Acceptance criterion | The observable check that proves a fix works on retest. |

## Appendix E: Previous audit

Not applicable. No earlier report or findings file was supplied. See Appendix C for the reference to `findings.jsonl.bak`, which is not present in this working copy.
