# Benchmark Report — Cyber Intelligence GraphRAG

_Generated 2026-10-20T16:25:33+00:00 by `evaluation/run_benchmark.py` — do not edit by hand; re-run the script._

## Setup

- **Ground truth:** `injected` — INJECTED scenarios (no answer key found in data/raw/answers): 12 insiders (S1=4, S2=4, S3=4) among 60 real demo users; benign users are unlabelled real CERT users
- **Log data:** `demo` CERT r4.2 (committed demo subset), 60 users (12 insiders / 48 benign), 12,901 log rows (168 malicious)
- **Graph:** 6,608 nodes, 36,317 edges
- **Verdict model:** `template-fallback` ×60
- **Detection rule:** user flagged when checked risk ≥ 0.4 (the `suspicious` verdict boundary); seed 42

## Table 1 — Headline metrics

| Metric | Value | Definition |
|---|---|---|
| Retrieval accuracy (F1) | 0.319 | Macro-F1 of entities on verified evidence paths vs entities of each insider's malicious events |
| Graph completeness | 100.0% | Entities in graph / entities derivable from the ingested log rows |
| Threat-correlation precision | 0.440 | Share of asserted (user → ATT&CK technique) links that are true malicious links |
| Response time | 3.05 s indexing · 17 ms/query | Graph build once; mean end-to-end query (retrieve → verdict → groundedness → confidence) |
| Detection effectiveness | P 0.636 · R 0.583 · F1 0.609 · FPR 0.083 | Per-user insider detection vs labels |

## Table 2 — Detection: full system vs ablation vs naive baseline

| Variant | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| Full system (peer baseline + confidence propagation) | 0.636 | 0.583 | 0.609 | 0.083 | 7 | 4 | 5 | 44 |
| Ablation: no peer-prevalence discount | 0.300 | 1.000 | 0.462 | 0.583 | 12 | 28 | 0 | 20 |
| Naive baseline: any ATT&CK match ⇒ insider | 0.200 | 1.000 | 0.333 | 1.000 | 12 | 48 | 0 | 0 |

## Table 3 — Threshold sweep (full system)

| Risk threshold | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|
| 0.2 | 0.444 | 1.000 | 0.615 | 0.312 | 12 | 15 |
| 0.3 | 0.579 | 0.917 | 0.710 | 0.167 | 11 | 8 |
| 0.4 | 0.636 | 0.583 | 0.609 | 0.083 | 7 | 4 |
| 0.5 | 1.000 | 0.250 | 0.400 | 0.000 | 3 | 0 |
| 0.6 | 1.000 | 0.083 | 0.154 | 0.000 | 1 | 0 |
| 0.7 | 1.000 | 0.083 | 0.154 | 0.000 | 1 | 0 |

## Table 4 — Detection by insider scenario

| Scenario | Description | Insiders | Detected | Mean risk |
|---|---|---|---|---|
| S1 | after-hours logins + removable media + upload to WikiLeaks | 4 | 3 | 0.430 |
| S2 | job-site browsing, then data theft over a thumb drive | 4 | 1 | 0.355 |
| S3 | disgruntled admin: keylogger, supervisor-PC login after hours, mass external email | 4 | 3 | 0.556 |
| benign | unlabelled real users | 48 | 4 flagged (FP) | 0.132 (max 0.436) |

## Table 5 — Retrieval and threat correlation

| Measure | Precision | Recall | F1 |
|---|---|---|---|
| Evidence-entity retrieval (macro over insiders) | 0.736 | 0.240 | 0.319 |
| (user, technique) correlation | 0.440 | 0.500 | 0.468 |

ATT&CK coverage of malicious events (expected = hand-labelled, found = asserted by the system):

| Technique | Expected links | Found |
|---|---|---|
| T1005 | 8 | 4 |
| T1048 | 4 | 0 |
| T1052 | 12 | 7 |
| T1056 | 4 | 0 |
| T1078 | 8 | 6 |
| T1567 | 8 | 5 |

Graph completeness: 6,601 of 6,601 expected entities present.

## Table 6 — Response time

| Phase | Calls | Mean | p50 | p95 | Max |
|---|---|---|---|---|---|
| indexing | 1.0 | 3050.9 ms | 3050.9 ms | 3050.9 ms | 3050.9 ms |
| retrieval | 60.0 | 11.5 ms | 8.6 ms | 17.3 ms | 80.2 ms |
| reasoning | 60.0 | 2.2 ms | 1.5 ms | 4.6 ms | 8.2 ms |
| groundedness | 60.0 | 0.9 ms | 0.7 ms | 1.6 ms | 3.4 ms |
| query_total | 60.0 | 16.7 ms | 12.2 ms | 30.2 ms | 88.8 ms |

## Table 7 — Groundedness self-check (core contribution)

Live verdicts: grounded ×60.

Fault injection: a simulated hallucinating LLM appends a fabricated edge id to 30.0% of verdicts; each regeneration is still hallucinated with probability 50.0%.

| Measure | Value |
|---|---|
| Verdicts with a fabricated citation | 15 |
| Caught by the checker (catch rate) | 15 (100.0%) |
| Recovered by constrained regeneration | 10 |
| Flagged `[unverified]` + risk downgraded 20% | 5 |
| Total regeneration calls | 25 |
| False alarms on clean verdicts | 0 of 60 (0.0%) |

## Threats to validity

- With `injected` ground truth the insider behaviour is synthetic (modelled on the published CERT r4.2 scenarios) and the "benign" users are unlabelled real users, a few of whom may be genuine insiders. Re-run after `python scripts/fetch_cert_data.py answers` to evaluate against the official answer key.
- In offline mode verdicts come from the deterministic evidence template, which is grounded by construction; the fault-injection table is what exercises the groundedness checker. Re-run with `--llm` to measure a real model.
- The detection threshold is the fixed verdict boundary, not tuned on this data; Table 3 shows the trade-off.
