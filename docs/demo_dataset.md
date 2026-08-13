# Demo Dataset

A trimmed, self-contained subset of the CERT r4.2 insider-threat logs, committed
to the repository so the pipeline can run **without downloading the ~16 GB
full dataset** — ideal for demos, CI, and offline presentation environments.

## Contents

| File | Rows (demo) | Rows (full) | Size |
|---|---|---|---|
| `logon.csv` | 165,686 | 854,859 | ~11 MB |
| `device.csv` | 82,068 | 405,380 | ~6 MB |
| `file.csv` | 113,641 | 445,581 | ~47 MB |
| `email.csv` | 59,719 | ~2,629,980 | ~30 MB |
| `http.csv` | 136,052 | ~28,434,424 | ~66 MB |
| **Total** | | | **~159 MB** |

## How the subset was chosen

The subset is built deterministically by `scripts/build_demo_dataset.py`
(fixed random seed 42, so every run produces identical files):

1. **200 core users** are sampled from `logon.csv`; **100% of their rows** are
   kept in every log. This preserves complete behavioral traces for a large
   user population — every activity type (logins, device connections, file
   access, email, web traffic) stays fully correlated for those users.
2. In the two huge logs (`email.csv`, `http.csv`) the core users are further
   capped per user (200 / 400 rows) to bound the size, and a small
   **hash-based sample of non-core users** (0.5% / 0.05%) is kept so the graph
   still shows general network structure in visualizations.
3. The user list itself is stored as a byproduct of the build and could be
   persisted to `data/demo/users.txt` if later weeks need it.

Total size is ~159 MB — every file stays under GitHub's 100 MB per-file
upload limit, so the demo set is committed to the repo directly (no
`git lfs` or zip extraction needed on the user's PC).

## Usage

All tooling auto-falls-back to the demo data when the full dataset is absent:

```bash
# The explore script prefers data/raw/ but uses data/demo/ automatically
python3 scripts/explore_cert.py              # raw if present, else demo
python3 scripts/explore_cert.py --demo       # force the demo subset

# Tests behave the same way — they pass with demo data alone:
python3 -m pytest tests/test_data_loading.py
```

The resolution order in code is: `data/raw/<csv>` → `data/raw/r4.2/<csv>`
(Kaggle mirror layout) → `data/demo/<csv>`.

## Rebuilding

```bash
python3 scripts/build_demo_dataset.py              # rebuild with default seed
python3 scripts/build_demo_dataset.py --seed 7     # different user set
```

Rebuilding requires the full dataset in `data/raw/r4.2/`. The committed demo
files should not be regenerated unless intentionally changing the subset.

## Notes

- The demo subset is drawn from the same Kaggle mirror as the full data, so
  its columns are identical (`id, date, user, pc, ...` — see
  `docs/cert_dataset_notes.md`).
- The insider-label answer key is not part of the demo set either; insider
  scenarios can still be hand-picked from the 200 core users for demos
  (their full traces are preserved, so anomalous patterns are observable).
- Not for research-grade analysis — the sampling is designed for functional
  demos and visualization, not statistical fidelity.
