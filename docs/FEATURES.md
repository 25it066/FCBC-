# FCBC feature contract: 2.0-research-1

Source: PDL-1 REPORT.docx, sections 5.6 and 6.5. The source defines the roles of D, C, P, X and B but explicitly leaves numeric definitions to implementation. The following formulas are NEW research choices, not validated formulas quoted from the report. Freeze configuration before held-out evaluation.

## Identity and episodes

Identity = (host_id, session_id, file_namespace, file_id). All four must be supplied. A namespace is a collector-defined volume or file-ID namespace, not a fabricated file ID. Do not map a constant into a namespace unless the collector contract actually guarantees it. Unknown identities remain in the event explorer; they are excluded from episode construction. No path-based merging. Collectors must distinguish file-ID reuse across generations: this implementation does not infer generation identifiers.

Sort recorded events by timestamp, host, session and event ID. This is offline replay, not streaming-watermark analysis. A new episode begins after an idle gap strictly greater than episode_gap seconds. Stable IDs retain continuity across path changes; path-only relationships never create identity. A rename link is verified only when an earlier event in that episode observed rename_source, the rename carries distinct source and target, its current path equals target, and scoped stable identity matches. Equal timestamps do not establish order. No cross-ID rename linking is attempted. Rename ablation disables verified links, while stable-ID identity remains intact.

Windows are separated by host/session. Their first start is the first event in each scope; starts advance by stride seconds through the last event. Membership is [start, start + duration). A window ending after the last recorded event is marked incomplete; include or drop is configurable. The last observed event is only a conservative completeness proxy, not proof of collector coverage. Long idle periods and excessive overlap are bounded (10,000 windows and 250,000 total event references per run).

Episodes are rebuilt inside each window so feature evidence never reaches outside that window. EP IDs in a window are local to that window. Global result episodes are separately constructed over the whole dataset; use identity plus scoped source event references to compare them, not bare EP IDs.

## Definitions

Let N be the number of known-identity episodes in the window. Each feature lies in [0,1] when available. No learned scaling is applied.

| Feature | Formula | Requirements / missingness |
|---|---|---|
| D | Number of episodes with a Write strictly before either a Delete or a verified Rename, divided by N | Stable identities; null when N=0 |
| C | Number of episodes involving at least two observed process IDs, divided by N | Every event in the eligible episodes must have a process ID; otherwise null |
| P | Number of episodes with strictly ordered Read → Write → (Delete or verified Rename), divided by N | Stable identities; null when N=0; ties never satisfy progression |
| X | Count of configured destructive operations divided by total events | Default set: Write, Rename, Delete; this is only an operation proxy, not proof of destructive intent |
| B | Fraction of Read, Create or Metadata change events when separate trusted benign context exists | External admin attestation or explicitly synthetic fixture provenance; otherwise null. Never inferred from filenames, process names, source `authorized` fields or labels |

S = wD·D + wC·C + wP·P + wX·X − wB·B. Contributions are rounded to eight decimals. No clamping or conversion to a probability is applied. Default weights = .35, .20, .25, .20, .20, threshold = .55. These are illustrative, uncalibrated research parameters.

Unknown B contributes no discount, but remains null in output with a warning. Missing required D/C/P/X (for a nonzero configured weight), or identity coverage below min_identity_coverage, produces a null score and `Insufficient telemetry`. Do not treat this as a low-risk result. Coverage = events in known-identity episodes / all events.

Scores >= threshold receive `Review`; other eligible scores receive `Below threshold`. Neither is a malware diagnosis. Analyst review status is independent of the scoring classification and independent of dataset labels.

## Evaluation

The included lab uses 36 deterministic synthetic executions: 18 validation and 18 test, with three repeats of each of six scenarios per partition. Group assignment and unique session IDs occur before window creation. Weights are fixed research settings, so no training split is used. Each detector is threshold-calibrated using maximum validation F1, breaking ties toward a higher threshold, then frozen for held-out testing. Predictions are execution-level; FCBC uses the maximum eligible window score.

Baselines use maximum event count per process in the execution and total event volume per execution, respectively. Ablations: disable verified rename evidence; separate the execution by process before episode/window generation and zero C; or zero B. All use the same complete held-out executions. The experiment stores every score, label, group, dataset hash, threshold and configuration. Confusion-matrix ratios with no denominator are null, not misleading zeros.

Synthetic fixtures are deliberately simple and can yield perfect scores. Those values ONLY describe those generated fixtures. No authorized malware trace or independent production dataset was supplied. Real-world accuracy, precision, recall and calibration remain unmeasured.
