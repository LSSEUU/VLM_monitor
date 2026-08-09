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
- Case state: `CLOSED`, revision `5`
- Final decision: `ESTABLISHED`
- Alert level: `CONFIRMED`
- Alert ID: `c492c8e7c5af2310087f37cbc9f392723aa3c77951565df998fa4b46f03f0314`
- Local alert document ID: `0ece6c9a2f6cfe1c2e1a60e6bd6ef4ac86513044da44ff4c07664a5f60826d42`
- Metrics ID: `325b102c199e22660a50acd5039b0c3f38ab6feeb0371f36f78474cd6d577887`
- Final replay publication ID: `1f61d4124bc0382c152ef31cd733db20bc3889f2b9e9168aa09924c9e151f09a`
- Human appeal/review: none submitted.

All five report media entries were re-read from disk and matched their authoritative SHA-256
values. The report intentionally omits raw model narrative and shows only structured screening,
deterministic verdict, procedural-review, alert, version, and evidence facts.

## Published Files

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `metrics.json` | 3,986 | `ebea99088203fdfd04266a93554c2fbb98796de72ee689b20652089cae7d07ae` |
| `report/index.html` | 10,535 | `40e2a6c3077a0c85cbd7d572c7b60c093a266f19ab9d94c2199a9775c97bcdf1` |
| `report/cases/2ee434cc-3f72-58a4-8992-19b39a20788d.html` | 13,335 | `18d2ef885516f7842dfb5ca9a362be00658ceaa453fd6ea073c52a0435470925` |
| `alerts/c492c8e7c5af2310087f37cbc9f392723aa3c77951565df998fa4b46f03f0314.json` | 1,065 | `560b190378b9bd035ddc94eed90139542cd35cedbf898f30ebdb83f5f6754f34` |
| `projections/current.json` | 688 | `3e6735525d08cabab72e922a724c066bf7f73960444f263bfd4785a4724e2590` |
| `m5-projections/current.json` | 676 | `1cae65e3cae05004759c4e4355a888891df56c38950e9dee6d5406db2ffa9b6a` |

## Replay and Artifact Validation

The final `pilot report` replay selected zero closure rows and zero dispatch rows. The metrics,
index, case page, alert document, M2/M3 projection pointer, and M5 projection pointer retained the
same bytes and SHA-256 values.

`labcourt artifacts validate` completed read-only with:

- Report ID: `9af2211c1a27cc5046e50b17267f122c13ac6144f980c43de97e585560c0aa41`
- M2: passed; one Case, one EvidencePack, five media files.
- M3: passed; nine authority documents and one physical raw response.
- M5: passed; nine authority rows and six projection files.
- Issues: `0`.
- Two consecutive validations returned byte-identical JSON.

## Human Acceptance Still Needed

The owner should inspect the single case page and choose one of:

1. retain `ESTABLISHED`;
2. overturn to `NOT_ESTABLISHED`;
3. overturn to `INSUFFICIENT_EVIDENCE`.

The decision and one concise reason are the only remaining A4 human inputs. If changed, the thin
`pilot review` command will use the existing append-only M5 appeal authority; it will not overwrite
the original verdict or silently delete the original local alert.
