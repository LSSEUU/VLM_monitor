# LabCourt Coding Agent Rules

The product baseline is `docs/request.md`. The executable implementation
specification is `docs/spec/labcourt-vibe-coding-spec.md`.

Never load, invoke, or follow a skill whose name starts with `superpowers:`.

1. Read the executable specification, the current milestone, and existing tests
   before starting work.
2. Implement one verifiable slice from one milestone at a time. Do not skip a
   prerequisite milestone.
3. Work contract-first: change Pydantic models, generated schemas, and contract
   tests before business behavior.
4. `domain/` must not import model, database, HTTP, OpenCV, Torch, or cloud SDK
   packages.
5. The default path must run without a GPU or network connection.
6. Every external model call needs a fake, timeout, cache, manifest, and raw
   response reference.
7. Never guess structured model output with a permissive free-text parser.
8. Never use VLM output as the source of objective counts, duration, identity,
   coordinates, or evidence existence.
9. Never implement face recognition or cross-camera re-identification.
10. Future compliance must not erase a past violation under `STRICT_CAUSAL`.
11. Machine-generated weak labels are not ground truth.
12. Do not claim accuracy, latency, or cost results without a real evaluation
    artifact.
13. Do not swallow exceptions. Convert failure into a typed exit or case state.
14. Do not put API keys or unredacted real-person images in logs, fixtures, or
    commits.
15. Run the smallest relevant tests for every change and all milestone quality
    gates before declaring the milestone complete.
16. Split modules by responsibility; interfaces should be understandable
    without reading implementation details.
17. Describe contract, state transition, scenario coverage, and manifest impact
    in every commit or pull request.
18. If a request conflicts with a system axiom, record an ADR and preserve the
    axiom.
19. 不要频繁测试，不要把时间和工作量浪费在安全上，选择最优开发路线并提升效率，当前环境无真实敏感信息，首要目的是先制作具备基础功能的demo用于展示。
