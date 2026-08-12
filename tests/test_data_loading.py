"""Week 2 — tests/test_data_loading.py

Asserts each raw CERT r4.2 CSV loads without error and has at least 1 row.

These tests are skipped (not failed) when the raw CSVs are absent, so the
suite still passes in CI environments without the ~4.5 GB dataset — but the
"Done when" check requires the data to be present and all tests to run.
"""
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = REPO_ROOT / "data" / "raw"
KAGGLE_NEST = DATA_RAW / "r4.2"  # Kaggle mirrors nest the CSVs under r4.2/

CSV_FILES = ["logon.csv", "device.csv", "file.csv", "email.csv", "http.csv"]


def require_data(csv_name: str) -> Path:
    path = DATA_RAW / csv_name
    if not path.exists() and KAGGLE_NEST.exists():
        path = KAGGLE_NEST / csv_name
    if not path.exists():
        pytest.skip(f"{csv_name} not found at {DATA_RAW / csv_name} or {KAGGLE_NEST / csv_name}; fetch the dataset first")
    return path


@pytest.mark.parametrize("csv_name", CSV_FILES)
def test_csv_loads_without_error(csv_name: str) -> None:
    """Each raw CSV must load with pandas without raising an exception.

    Huge logs (http.csv, email.csv) are read in chunks so this test stays
    memory-safe on CI runners.
    """
    import pandas as pd

    path = require_data(csv_name)
    if csv_name in ("http.csv", "email.csv"):
        rows = 0
        for chunk in pd.read_csv(path, chunksize=100_000):  # raises on malformed data
            rows += len(chunk)
        assert rows > 0
    else:
        df = pd.read_csv(path)  # raises on malformed data
        assert df is not None


@pytest.mark.parametrize("csv_name", CSV_FILES)
def test_csv_has_at_least_one_row(csv_name: str) -> None:
    """Each raw CSV must contain at least 1 row of data."""
    import pandas as pd

    path = require_data(csv_name)
    if csv_name in ("http.csv", "email.csv"):
        for chunk in pd.read_csv(path, chunksize=100_000):
            assert len(chunk) >= 1, f"{csv_name} is empty"
            break
    else:
        df = pd.read_csv(path)
        assert len(df) >= 1, f"{csv_name} is empty"


# NOTE: this local mirror (Kaggle utkarshkanwat/certr42) ships the CSVs with a
# slightly different schema than the classic "official release" column names
# (user/pc/d/t). The columns below are the *measured* ones from the actual
# files and are the ones the pipeline must consume. If you replace the mirror
# with the official CMU release, update these lists accordingly.
@pytest.mark.parametrize(
    "csv_name,expected_columns",
    [
        ("logon.csv", ["id", "date", "user", "pc", "activity"]),
        ("device.csv", ["id", "date", "user", "pc", "activity"]),
        ("file.csv", ["id", "date", "user", "pc", "filename", "content"]),
        ("email.csv", ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"]),
        ("http.csv", ["id", "date", "user", "pc", "url", "content"]),
    ],
)
def test_csv_has_expected_columns(csv_name: str, expected_columns: list[str]) -> None:
    """Each CSV must expose the columns needed for behavior modeling."""
    import pandas as pd

    path = require_data(csv_name)
    # http.csv/email.csv are huge; read only a chunk for the column check
    if csv_name in ("http.csv", "email.csv"):
        df = pd.read_csv(path, nrows=10)
    else:
        df = pd.read_csv(path)
    missing = [c for c in expected_columns if c not in df.columns]
    assert not missing, f"{csv_name} missing expected columns: {missing}"
