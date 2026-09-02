# A4 Operator Report Check — 2026-08-09

## Scope

- Source run: `a3-qwen-missing-20260809-v9`
- Source RunManifest code commit: `803ff1a`
- A4 implementation commits: `5e1c57b`, `813a8c6`, `acee10d`
- Run manifest: `e0ba601f3b083ba6d1f3bf561f8883fa9150cae77f80c91093ea51a73c45f0f3`
- Config SHA-256: `e67502ed87615983038e6e70bb1d342d9e2055e2e6c52dd6d38df90c30f972d6`
- Delivery boundary: local JSON only; production delivery count `0`
- No detector or VLM provider was called during A4.

This check establishes the local A4 engineering path only. It does not establish detector/VLM
accuracy, real-site readiness, or a punishment-grade decision.

## Authoritative Result

- Case: `2ee434cc-3f72-58a4-8992-19b39a20788d`
- Case state: `APPEAL_RESOLVED`, revision `8`
- Final decision: `ESTABLISHED`
- Alert level: `CONFIRMED`
- Alert ID: `c492c8e7c5af2310087f37cbc9f392723aa3c77951565df998fa4b46f03f0314`
- Local alert document ID: `0ece6c9a2f6cfe1c2e1a60e6bd6ef4ac86513044da44ff4c07664a5f60826d42`
- Metrics ID: `cf5092075259fd3361a166895a390363fad69b6a0897dbfb314c6fe7c26bc399`
- Final replay publication ID: `424e03267bc794fc2a0224743209b7d20d1e9e7572d9c386f958d1fad3b548db`
- Human appeal/review: `UPHELD` by the fixed local operator identity
  `pilot-local-operator`.
- Appeal ID: `6c3910cc7f25c3e05485d5c8a2f1dbaed9cbbfaf6393d981def6c92bc7695092`
- Review ID: `612ef5b6f8a794e8bcda863b5ef896381d1b36053aeafa6d225a4583c4049ea1`
- Review reason SHA-256: `93fb4fd877180e9214181063f0c934e6838aa17c2459b6f912a8491edbc070e3`

All five report media entries were re-read from disk and matched their authoritative SHA-256
values. The report intentionally omits raw model narrative and shows only structured screening,
deterministic verdict, procedural-review, alert, version, and evidence facts.

## Published Files

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `metrics.json` | 3,999 | `4ec8cab5e1eedd37c293181a50887118be89451b489d2b1247611c4c02b539da` |
| `report/index.html` | 10,544 | `0f7ab73aed0384a94f95b044ad210ee40bd5e8829b222dddc8bef8bf212fb35e` |
| `report/cases/2ee434cc-3f72-58a4-8992-19b39a20788d.html` | 13,347 | `46425ed5d8783f33fd171be183b3bdfb8b343029eabdcd50e131635b676164d8` |
| `alerts/c492c8e7c5af2310087f37cbc9f392723aa3c77951565df998fa4b46f03f0314.json` | 1,065 | `560b190378b9bd035ddc94eed90139542cd35cedbf898f30ebdb83f5f6754f34` |
| `projections/current.json` | 688 | `48646af53c5d42183f6cb0485dd581d423c87d9fd50efe2a5e757f4cd2e032f8` |
| `m5-projections/current.json` | 676 | `43625d091804182d257b8ef52619b1ed5b8342d402d2fe97baf09404c90023f7` |

## Replay and Artifact Validation

The final `pilot report` replay selected zero closure rows and zero dispatch rows. The metrics,
index, case page, alert document, M2/M3 projection pointer, and M5 projection pointer retained the
same bytes and SHA-256 values.

The `pilot review` command was executed twice with the same explicit decision and reason. Both
executions returned byte-identical JSON and the same review, appeal, revision, metrics, and
publication identities. The second publication replay selected zero closure rows and zero dispatch
rows. The original alert document retained its exact pre-review bytes because an upheld review does
not rescind it. No training label was created because the decision was not overturned.

`labcourt artifacts validate` then completed read-only with:

- Report ID: `6b350c3d302e9c33e84e87a507ad3e8c097603b3ac53144d95922a0d5af11453`
- M2: passed; one Case, one EvidencePack, five media files.
- M3: passed; nine authority documents and one physical raw response.
- M5: passed; fifteen authority rows and six projection files.
- Issues: `0`.
- Two consecutive validations returned byte-identical JSON with output SHA-256
  `b9d16525aef81c7be9986946ef92c15b6f7d6f4446209c2047287bab3a757439`.

## Human Acceptance

The project owner inspected the single case and explicitly chose to retain `ESTABLISHED` on
2026-08-09. The existing append-only M5 appeal state machine recorded the decision as `UPHELD`;
the original verdict, active local alert, and full appeal history remain available for audit.

This completes A4 human acceptance. It is still a local engineering acceptance and does not turn
the model result into ground truth or authorize production delivery or disciplinary use.
