# CERT r4.2 Dataset Notes

Week 2 artifact — CERT dataset exploration notes. All `[TODO]` markers below were
replaced with values measured by running `python3 scripts/explore_cert.py`
(locally on 2026-08-12). This document ships with no placeholders.

## Source

| Item | Value |
|---|---|
| Dataset | CERT Insider Threat Test Dataset, Release 4.2 |
| Producer | CERT Division / CMU Software Engineering Institute (with ExactData, LLC; DARPA I2O) |
| Official archive | <https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247> (CC BY 4.0) |
| Local fetch helper | `scripts/fetch_cert_data.py` (official archive) |
| Local mirror actually used | Kaggle `utkarshkanwat/certr42` — a faithful upload of the same r4.2 CSVs |

> Column-note: the Kaggle mirror ships the CSVs with a slightly different
> schema than the one described in some papers that use the "official
> release" (those cite columns such as `d`/`t` for day-of-year/second-of-day).
> Everything below reflects the **columns actually measured in our local
> files**, which is what the pipeline must consume. If the repo later swaps
> to the official CMU tarball, `tests/test_data_loading.py` carries a comment
> pointing at where to update the expected column lists.

## What each CSV represents

The five logs together reconstruct one simulated year of enterprise activity
(1,000 synthetic users across 2010-01-02 .. 2010-12-31 in the local mirror).
Every row is one atomic security event tied to a user and a workstation, and
each row carries a globally unique event `id` of the form
`{AAAA-BBBBBBBB-CCCCCCCC}`.

| CSV | Represents | Rows (measured) | Columns (measured) |
|---|---|---|---|
| `logon.csv` | Authentication events — every logon/logoff of a user on a workstation | 854,859 | `id`, `date`, `user`, `pc`, `activity` (`Logon` 470,591 / `Logoff` 384,268) |
| `device.csv` | USB/removable-device connections (Connect/Disconnect pairs) | 405,380 | `id`, `date`, `user`, `pc`, `activity` (`Connect` 203,339 / `Disconnect` 202,041) |
| `file.csv` | File-system events — file handling with magic-byte signature and extracted text | 445,581 | `id`, `date`, `user`, `pc`, `filename`, `content` |
| `email.csv` | SMTP events — sender, recipients, size, attachment count, content keywords | ~2,629,980 | `id`, `date`, `user`, `pc`, `to`, `cc`, `bcc`, `from`, `size`, `attachments`, `content` |
| `http.csv` | Web traffic — URLs visited per user/workstation with content keywords | ~28,434,424 | `id`, `date`, `user`, `pc`, `url`, `content` |

Date format in all logs: `MM/DD/YYYY HH:MM:SS` (real calendar timestamps in the
local mirror, not synthetic `d`/`t` values).

## Columns that matter for behavior modeling

The behavior-modeling core is the five-tuple **(user, timestamp, device/host,
action, target)**; the mapping per log is:

| Dimension | logon.csv | device.csv | file.csv | email.csv | http.csv |
|---|---|---|---|---|---|
| **user** | `user` | `user` | `user` | `user` | `user` |
| **timestamp** | `date` (MM/DD/YYYY HH:MM:SS) | `date` | `date` | `date` | `date` |
| **device/host** | `pc` (workstation) | `pc` | `pc` | `pc` | `pc` |
| **action** | logon vs. logoff (two row types) | Connect vs. Disconnect | file handling (one row per event) | sent/received (direction from `from` vs. `to`/`cc`/`bcc`) | URL visit |
| **target** | workstation id | device event pair | `filename`, `content` (magic bytes + extracted text) | recipients `to`/`cc`/`bcc` (semicolon-separated lists), `size`, `attachments` | `url`, `content` keywords |

Behavioral signals of interest per the weekly plan:

- **Off-hours login** → T1078 (logons outside the workday window in `date`).
- **USB data staging** → T1052 (device `Connect`/`Disconnect` pairs whose
  subsequent file activity indicates data copied to removable media).
- **First-time/unusual file access** → T1005 (files in `filename` accessed by
  users without prior history).
- **Data exfiltration via email** → T1567 (`email.csv` rows with large `size`
  and attachment content sent to external recipients).
- **Large data transfer over HTTP** → T1030 (unusual URLs / content categories
  in `http.csv`).

A few field quirks worth recording: in `email.csv`, `to`, `cc`, and `bcc` are
semicolon-separated address lists (some rows leave them empty); `size` is a
decimal string of bytes (e.g. `25830`); `attachments` counts attachment files.
In `file.csv`, `content` begins with the file's hex magic bytes
(e.g. `D0-CF-11-E0...` for Office docs) followed by extracted text. The local
mirror's `device.csv` does **not** carry a per-device content listing — the
Connect/Disconnect event pairs are the available signal, and file-access
correlation must supply the rest.

## Answer key / insider labels

The official answer key (`answers.tar.bz2`, extracted to `data/raw/answers/`)
contains one `.answers` file per log with rows describing each malicious
scenario and the user ids involved; user ids follow the pattern `[A-Z]{3}\d{4}`
(e.g. `CDE1846`). The local Kaggle mirror does **not** include the answer key,
so the labeled-user count is skipped for now:

> Insider-threat-labeled users counted from the key: *not available locally —
> fetch `answers.tar.bz2` from the official KiltHub archive (see
> `scripts/fetch_cert_data.py`) when insider labels are needed.*

## Caveats

- The local mirror uses real calendar `date` columns (`MM/DD/YYYY HH:MM:SS`),
  unlike some literature that describes synthetic `d`/`t` (day-of-year /
  second-of-day) fields; the ingestion layer must parse the mirror's format
  first and re-evaluate after any archive swap.
- The data is fully synthetic — it models realistic behavior but should not be
  treated as real telemetry.
- Some rows in `file.csv` and `http.csv` record system/background activity
  (non-user events); they should be filtered during ingestion.
- `http.csv` (~14.5 GB) and `email.csv` (~1.27 GB) are too large to load
  naively into memory; exploration and ingestion should use chunked reading
  (`pd.read_csv(nrows=..., chunksize=...)` or line-based tools), which is how
  `scripts/explore_cert.py` already handles them.
- Disk: the full five-CSV set occupies ~16 GB on disk; `.gitignore` excludes
  `data/` so the raw files are never committed to the repo.
