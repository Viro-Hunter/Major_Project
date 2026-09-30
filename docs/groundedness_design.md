# Groundedness Checking: Design Decision

## Problem

The verdict generator is an LLM. Given a subgraph, it returns a narrative, a
`risk_score` and a list of `cited_edges`. Nothing forces those citations to be
real: a model can cite an edge id that is not in the subgraph, or that never
existed. An analyst reading "risk 0.9, evidence: e99" cannot tell that e99 is
fabricated, and the system's headline output then rests on evidence that does
not exist. This is worst in a security setting, where the verdict drives
automated actions (IP block, forced re-auth) via `action/gate.py`.

## Decision

A required step, `check_groundedness(verdict, subgraph)`, sits between
`verdict_generator` and the API response.

1. **Verify.** Every id in `verdict["cited_edges"]` must exist in `subgraph.edges`.
2. **Repair.** If any is missing, call the generator again with an explicit
   instruction listing the only permitted edge ids. Maximum 2 retries.
3. **Degrade safely.** If the verdict is still ungrounded, multiply `risk_score`
   by 0.8 and append `[unverified]` to the explanation. The result is shown
   as *less confident and labelled*, never as a clean high-confidence result.

Every returned verdict carries a `groundedness` block (`status`:
`grounded | regenerated | unverified`, `retries_used`, `missing_edges`,
`verified_edges`) so the audit trail and dashboard can show exactly what
happened.

### Why these choices

- **Deterministic check, not another LLM.** Set membership is exact, free and
  cannot itself hallucinate.
- **Retry with a constraint, not a bare retry.** Telling the model the allowed
  ids turns an open generation problem into a closed one; most failures should
  resolve on the first retry.
- **Bounded retries.** Caps latency and cost per incident (at most 3 generator
  calls).
- **Downgrade rather than reject.** Dropping the incident would hide a
  potential threat. Lowering the score pushes the case toward the analyst
  queue (`ACTION_ANALYST_THRESHOLD`) and away from auto-execution
  (`ACTION_AUTO_THRESHOLD`), so an unverified verdict is far less likely to
  trigger an automated action on its own.
- **Failures are fail-safe.** A generator exception during a retry counts as a
  failed attempt, and the same downgrade path applies.

### Known limits

- The check proves cited edges *exist*, not that they *support* the claim. A
  real edge can still be cited for the wrong conclusion. Semantic support
  checking (edge type vs. claim) is a natural extension.
- A verdict with an empty `cited_edges` passes vacuously; it can be flagged
  later if you want to require at least one citation.

## Mapping to evaluation metrics

**Graph completeness.** This metric asks whether the conclusions the system
reports are actually backed by the graph. The checker enforces that mechanically:
every edge a shipped verdict relies on is verified to be present in the
retrieved subgraph, so reported reasoning paths can never extend beyond the
graph's real content. When the model reaches for an edge that is absent, that
is direct evidence of a gap between what the model believes and what the graph
holds; recording it in `missing_edges` makes those gaps measurable rather than
silent.

**Threat correlation precision.** This metric penalises correlations that are
asserted but wrong. A fabricated edge is a false correlation by construction:
it links entities the data never linked. Rejecting or repairing those
citations before they reach the response removes a class of false positives at
the source, and the 20% downgrade with the `[unverified]` flag prevents any
remaining unverifiable correlation from being presented, or acted on, with
full confidence.

## Report paragraph (contribution section)

> To keep LLM-generated verdicts faithful to the evidence graph, we introduce a
> deterministic groundedness gate between verdict generation and response. Every
> edge cited by a verdict is checked for membership in the retrieved subgraph;
> ungrounded verdicts are regenerated under an explicit allowed-edge constraint
> (at most two retries), and verdicts that remain ungrounded are labelled
> `[unverified]` and have their risk score reduced by 20%, steering them toward
> analyst review instead of automated action. This directly supports graph
> completeness, since every reported reasoning path is verified to exist in the
> graph, and threat correlation precision, since correlations the graph does not
> contain are prevented from surfacing as high-confidence findings. The gate
> also records which cited edges were missing, turning hallucinated evidence
> into a measurable signal rather than an invisible failure mode.

*Before submitting, replace or supplement this with measured numbers, for
example the fraction of verdicts that were grounded on the first pass,
recovered by retry, or ended `unverified`, and precision with and without the gate.*
