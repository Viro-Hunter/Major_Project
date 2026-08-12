#!/usr/bin/env python3
"""Fetch the CERT r4.2 insider-threat dataset from the official CMU KiltHub.

Downloads:
  - r4.2.tar.bz2   (~4.5 GB) -> extracted into data/raw/
  - answers.tar.bz2 (answer key with insider-threat labels) -> data/raw/answers/

Usage:
    python3 scripts/fetch_cert_data.py            # download both archives
    python3 scripts/fetch_cert_data.py r4.2       # only the dataset
    python3 scripts/fetch_cert_data.py answers    # only the answer key

Source: https://kilthub.cmu.edu/articles/12841247 (CC BY 4.0)

NOTE: the KiltHub servers can be slow or intermittently unreachable; the
script retries automatically. If it still fails, a faithful mirror of the
same CSVs lives on Kaggle at `utkarshkanwat/certr42` (requires a Kaggle
account) -- extract its r4.2/ CSVs into data/raw/r4.2/ instead. The answer
key is only available from the official KiltHub archive.
"""
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = REPO_ROOT / "data" / "raw"

FILE_IDS = {
    # (file_id_on_kilthub, output_name)  -- IDs may change; update if needed
    "r4.2": ("r4.2.tar.bz2", "https://kilthub.cmu.edu/ndownloader/files/20358249"),
    "answers": ("answers.tar.bz2", "https://kilthub.cmu.edu/ndownloader/files/20358247"),
}

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def download(url: str, dest: Path, max_attempts: int = 20) -> None:
    """Download with retries; resumes partial downloads."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, max_attempts + 1):
        print(f"[{dest.name}] attempt {attempt}/{max_attempts} ...", flush=True)
        rc = subprocess.call(
            [
                "curl", "-L", "--http1.1", "-A", UA, "--max-time", "300",
                "-C", "-", "-o", str(dest), url,
            ]
        )
        if rc == 0 and dest.exists() and dest.stat().st_size > 100_000:
            print(f"[{dest.name}] downloaded ({dest.stat().st_size:,} bytes)", flush=True)
            return
        if dest.exists() and dest.stat().st_size < 100_000:
            dest.unlink(missing_ok=True)
    raise SystemExit(f"[{dest.name}] failed after {max_attempts} attempts")


def extract(archive: Path, dest_dir: Path, flatten: bool = False) -> None:
    print(f"[{archive.name}] extracting to {dest_dir} ...", flush=True)
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:bz2") as tar:
        members = tar.getmembers()
        if flatten:
            # answers archive: pull every .answers / readme file to the top level
            for m in members:
                if m.isfile():
                    m_copy = tarfile.TarInfo(name=os.path.basename(m.name))
                    fh = tar.extractfile(m)
                    if fh:
                        with open(dest_dir / m_copy.name, "wb") as out:
                            out.write(fh.read())
        else:
            tar.extractall(dest_dir)
    print(f"[{archive.name}] extracted {len(members)} members", flush=True)


def main() -> int:
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["r4.2", "answers"]
    DATA_RAW.mkdir(parents=True, exist_ok=True)

    for key in targets:
        if key not in FILE_IDS:
            print(f"Unknown target: {key} (choose from {list(FILE_IDS)})")
            return 1
        name, url = FILE_IDS[key]
        archive = DATA_RAW / name
        download(url, archive)
        dest = DATA_RAW / "answers" if key == "answers" else DATA_RAW
        extract(archive, dest, flatten=key == "answers")
    return 0


if __name__ == "__main__":
    sys.exit(main())

