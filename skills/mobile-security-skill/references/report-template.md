# Final Report Template

`report-synthesizer` renders this skeleton twice, once per language, into `report/final-report.en.md` and `report/final-report.pt-BR.md`. Labels come from `report-i18n.md`: every `{{L_*}}`/`{{S_*}}`/`{{H_*}}` token is a key in that file, and every enum value (severity, status, attacker model, coverage) goes through its enum table. Finding IDs, CWE/MASVS/ref IDs, CVSS vectors, paths and code identifiers are never translated.

The HTML version uses the companion `report-template.html`. It is the primary deliverable, and both files must agree on every fact.

Fill every section; write `{{NONE_IDENTIFIED}}` rather than deleting a heading.

```markdown
# {{H_TITLE}}: {{APP_NAME}} {{APP_VERSION_OR_BUILD}}

> {{CLASSIFICATION_VALUE}}

| | |
|---|---|
| **{{L_PLATFORMS}}** | {{PLATFORMS}} |
| **{{L_FRAMEWORK}}** | {{FRAMEWORK}} |
| **{{L_ARTIFACT_SHA256}}** | `{{ARTIFACT_SHA256}}` |
| **{{L_WINDOW}}** | {{ASSESSMENT_DATES}} |
| **{{L_AUTHORIZATION}}** | {{AUTHORIZATION_ONE_LINE}} (see `scope.md`) |
| **{{L_TOOLS}}** | {{TOOLS_WITH_VERSIONS}} |

## {{S_EXEC}}
2-4 sentences, plain language, for a non-technical reader. Lead with the worst Confirmed finding if one exists, otherwise state the overall posture honestly ("no Confirmed findings; N Potential findings need follow-up"). Then give the count by severity and status, the top three risks by ID, and the headline recommendation.

Counts: {{COUNT_BY_SEVERITY_AND_STATUS}}

**Top risks:** {{TOP_3_RISKS}}

## {{S_SCOPE}}
{{SCOPE_IN_OUT_SUMMARY}}

## {{S_METHOD}}
- **Static analysis** (Phase 2): {{STATIC_SPECIALISTS_RAN}}
- **Dynamic analysis** (Phase 3): {{DYNAMIC_STATUS}}
- **Adversarial panel** (Phase 4): prosecutor and 2 to 3 skeptics per finding. Only the panel can produce Confirmed (see `severity-rating.md`).
- **Severity:** impact rating (`critical` to `low`), set from attacker model, asset sensitivity and blast radius.
- **CVSS 3.1:** every finding carries a base vector. The score is computed from it by `scripts/cvss31.py`. Where the CVSS band and the panel's severity differ by one band or more, the finding shows a **{{L_SEVERITY_NOTE}}**.

## {{S_COVERAGE}}
| {{H_COVERAGE_AREA}} | {{H_COVERAGE_STATUS}} | {{H_COVERAGE_FINDINGS}} |
|---|---|---|
{{MASVS_COVERAGE_ROWS}}

Each MASVS control is listed once: {{COVERAGE_STATUS_ENUM}}. A control marked "Not tested" with a reason in Appendix C is not a clean bill of health.

## {{S_SUMMARY}}
| {{H_NUM}} | {{H_FINDING}} | {{H_SEVERITY}} | {{H_STATUS}} | {{H_ATTACKER}} | {{H_CVSS}} | {{H_REFS}} |
|---|---|---|---|---|---|---|
{{SUMMARY_ROWS}}
<!-- Each row: | {{N}} | {{TITLE}} | {{SEVERITY}} | {{STATUS}} | {{ATTACKER}} | {{CVSS_SCORE}} `{{CVSS_VECTOR}}` | {{REF_IDS}} | ; the fact checker reads `{{finding_id}}` from the finding block heading below, so keep it there. -->

The parity checker reads each finding's `### {{finding_id}}:` heading and its `- **{{L_CWE}}:**` / `- **{{L_CVSS}}:**` lines, so their order must stay as in the block shape below.

Order: Confirmed first, then Potential, then Informational. Inside each status, sort by severity (critical to low), then by CVSS base score, descending. False positives are not in this table; they go in Appendix A.

## {{S_CONFIRMED}}
{{CONFIRMED_BLOCKS}}

Each finding block has this shape:

### {{finding_id}}: {{TITLE}}
- **{{L_SEVERITY}}:** {{SEVERITY}} · **{{L_STATUS}}:** {{STATUS}} · **{{L_ATTACKER}}:** {{ATTACKER}}
- **{{L_CWE}}:** {{CWE}} · **{{L_CVSS}}:** `{{CVSS_VECTOR}}` = {{CVSS_SCORE}} · **{{L_MASVS}}:** {{MASVS}}
- **{{L_SEVERITY_NOTE}}:** {{SEVERITY_NOTE_OR_OMIT}}
- **{{L_DESCRIPTION}}:** what the issue is, in the target's own component and class names.
- **{{L_ATTACK_PATH}}:** source -> propagation -> sink, with file:line at each hop.
- **{{L_REPRO_STATIC}}:** numbered steps a reviewer can repeat.
- **{{L_REPRO_DYNAMIC}}:** the exact command or hook, and the observed output. Or `{{NOT_APPLICABLE}}` with the reason.
- **{{L_EVIDENCE}}:** each artifact by path, with its SHA-256 where available.
- **{{L_PANEL}}:** 2 to 3 sentences on the specific refutation that failed, pointing at `exploitation/{{finding_id}}.md`.
- **{{L_REMEDIATION}}:** the specific fix, from the reference doc's fix column. For a resilience finding, add the server-side pairing.
- **{{L_ACCEPTANCE}}:** the observable check that proves the fix works on retest.
- **{{L_REFS}}:** {{REF_IDS}}

## {{S_POTENTIAL}}
Same block shape as Confirmed, plus:
- **{{L_WHY_NOT_CONFIRMED}}:** the specific evidence that would upgrade it. Take it from the prosecutor's "Gaps in current evidence" section. Name the device, build, or code needed.

## {{S_INFO}}
One line per item: `{{finding_id}}` · {{TITLE}} · {{REF_IDS}} · {{RATIONALE}} · {{REMEDIATION_SHORT}}

## {{S_PLAN}}
Ordered by priority, then by CVSS base score, descending.

| {{H_PRIORITY}} | {{H_FINDING}} | {{H_ACTION}} | {{H_VERIFY}} |
|---|---|---|---|
{{PLAN_ROWS}}

Priority is decided by the first rule that matches. Each finding gets exactly one priority:
1. **P1**: Confirmed and rated high or critical, at any impact.
2. **P1**: any finding rated high or critical whose impact is credentials, tokens, account data, a payment or transfer action, or a sandbox that holds them. This applies to Potential and Candidate findings too.
3. **P2**: any other Confirmed finding.
4. **P2**: any Potential finding rated high or critical that rule 2 did not catch.
5. **P2**: any medium-severity finding that exposes credentials or tokens.
6. **P3**: everything else, including informational items and candidates below high.

Rule 2 outranks rule 4, so a Potential High that exposes an account or sandbox is P1. The row states which rule applied, in one short phrase, so a reader can check it. Priority is a judgment about exposure, not a panel verdict.

## {{S_APPX_A}}
| {{H_FINDING}} | {{H_SUSPECTED}} | {{H_REFUTATION}} |
|---|---|---|
{{FALSE_POSITIVE_ROWS}}

Quote the skeptic's defeating fact verbatim where one exists.

## {{S_APPX_B}}
From `target-profile.md`: exported components, URL schemes and App/Universal Links, WebViews, network endpoints, permissions or entitlements, and third-party SDKs. Anything not determinable is written as "unknown", not "none".

{{ATTACK_SURFACE}}

## {{S_APPX_C}}
- **Specialists run:** {{SPECIALISTS_RAN}}, with the reference sections each covered.
- **Specialists skipped:** {{SPECIALISTS_SKIPPED_WITH_REASON}}.
- **Dynamic coverage:** {{DYNAMIC_COVERAGE}}. If no device was available, say so: STO/CRY runtime checks and ADV-60..72 need one.
- **Tools and versions:** {{TOOLS_WITH_VERSIONS}}.
- **Out of scope per `scope.md`:** {{OUT_OF_SCOPE}}.
- **Inconsistencies found during assembly:** {{INCONSISTENCIES_OR_NONE}}.

## {{S_APPX_D}}
| {{H_GLOSSARY_TERM}} | {{H_GLOSSARY_MEANING}} |
|---|---|
{{GLOSSARY_ROWS}}

## {{S_APPX_E}}
{{PREVIOUS_AUDIT_COMPARISON_OR_NOT_APPLICABLE}}
```

## Dedup rule before writing the summary table
Most duplicates are already merged in Phase 4 by fingerprint (see `SKILL.md`). This rule catches what the fingerprint missed. Multiple specialists can legitimately flag the same root cause from different angles (e.g. `taint-flow-analyst` flags a deep-link-to-WebView path that `webview-security-auditor` also flagged as a bridge-exposure issue). Merge into one finding entry, union the `ref_ids`, keep the higher of the two `severity_initial` values as a starting point for the panel, and note the merge in that finding's `notes`. Never report the same underlying bug twice under different IDs. A reader counting findings should get a true count of distinct issues.
