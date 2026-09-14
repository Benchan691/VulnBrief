# Goal: vendor/product filter at 100% eval accuracy — iterate until reached or you say stop

## Goal definition
Treat this as a standing goal, not a one-shot fix: keep improving the harness **and** the matcher in repeated iterations until the evaluation reports **100% accuracy — zero false positives and zero false negatives across every labeled case** — or until you say stop. Each iteration re-runs the live-data evaluation, and every newly discovered misclassification (FP or FN) is added to the labeled case set, so the target tightens as the harness learns; the loop only ends at a clean run or your stop.

## Working setup (from your earlier feedback)
- Harness lives in `eval/` in the workspace, isolated from the repo; only a one-line `.gitignore` entry for `eval/` is committed. No harness code ever enters version control.
- Database access to `mongodb://100.114.50.103:27017/` is strictly **read-only**.

## Iteration loop (repeat until 100% or stop)
**1. Profile/refresh real data (read-only)** — source collections (cve/zimbra/HPE/…), where vendor/product evidence actually lives, real stored inventories in `sub_account`.

**2. Run/extend harness** (`eval/`) — test inventories: real stored ones + rows derived from data + tricky synthetic rows. Measures per collection:
- *Candidate-pass recall (FN stage 1)*: Python reference net over all string fields vs the Mongo clause → field-path/regex coverage gaps.
- *Classifier FP inspection (stage 2)*: probable/possible matches dumped with evidence + suspicion signals (long segments, many other vendors in segment, CJK substring over-match).
- *Classifier FN probes*: exact "vendor product" phrases in title/description that classify as None; structured-pair matches that fail to yield confirmed.

**3. Adjudicate + grow labeled set** — each confirmed FP/FN becomes a labeled regression case (real document + expected verdict) stored with the harness; the accuracy metric = labeled cases passing / total.

**4. Fix the matcher** — current hypotheses (validated by data first): degenerate keys (`C++`→`c`, `.NET`→`net`) causing FP bombs; CJK substring over-match in possible tier; probable-tier gating blocked doc-wide by unrelated structured identities (FN on multi-product advisories); missing field paths found in profiling. Each fix lands with a regression test in `tests/subscriptions/test_vendor_products.py`.

**5. Re-measure** — accuracy table (labeled cases + tier distributions) after each fix; loop back to step 2 until 100% of labeled cases pass on a stable re-run, or you say stop.

## Ongoing deliverables
- After each iteration: short progress note with current accuracy vs. previous.
- At the end (goal reached or stop): before/after metrics, list of matcher changes with their regression tests, and notes on any new validation warnings for inventory authors.
- Repo changes limited to: matcher fixes + their tests + the `.gitignore` entry.