# Development

Back to [README](../../README.md)

## Easy development setup

```bash
git clone https://github.com/per2jensen/dar-backup.git
cd dar-backup/v2
./build.py
```

This script:

- Creates a Python virtual environment called `venv`
- pip install `hatch`
- pip install the development environment as setup in pyproject.toml

  ```text
  dev = [
  "pytest",
  "wheel>=0.45.1",
  "requests>=2.32.2",
  "coverage>=7.8.2",
  "pytest>=8.4.0",
  "pytest-cov>=6.1.1",
  "psutil>=7.0.0",
  "pytest-timeout>=2.4.0",
  "httpcore>=0.17.3",
  "h11>=0.16.0",
  "zipp>=3.19.1",
  "anyio>=4.4.0",
  "black>=25.1.0"]
  ```

Activate and run the test suite:

```bash
source venv/bin/activate # activate the virtual env
pytest                   # run the test suite
```

## Alternative: setup_environment.py

The easiest way to set up a fully reproducible environment is to
use the included helper script:

```bash
cd <path/to/dar-backup/v2>
./setup_environment.py
```

This will:

- Create a unique Python virtual environment (like venv or venv-YYYYMMDD-{N})
- Install all development dependencies listed in requirements-dev.txt
- Run build.sh to build the project wheel in the new environment

## Howto activate the venv

```` bash
cd <path/to/dar-backup/v2>
. venv/bin/activate
````

## Howto build & deploy to dev venv

Make sure __about__.py has the correct version number

```` bash
VERSION=$(cat src/dar_backup/__about__.py |grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(\.[[:digit:]]+)?')
python3 -m build && pip install --force-reinstall dist/dar_backup-${VERSION}-py3-none-any.whl
````

---

## Test coverage

### Test selection with markers

The test suite is annotated with these markers:

- `unit` (fast, pure logic)
- `component` (subprocess boundary with mocks/lightweight commands)
- `integration` (end-to-end workflows; external tools)
- `slow` (long-running/heavier integration)
- `live_discord` (sends real webhook messages; opt-in only)

### Common runs

```bash
# Fast local loop (unit + component)
pytest -m "unit or component"

# Integration (exclude slow + live webhook)
pytest -m "integration and not slow and not live_discord"

# Slow-only
pytest -m slow

# Full suite (default pytest.ini already excludes live_discord)
pytest -m "not live_discord"

# Live webhook (requires DAR_BACKUP_DISCORD_WEBHOOK_URL)
pytest -m live_discord
```

### Run all tests

```bash
pytest
```

### Howto use pytest in venv

The simplest way to run the test suite:

```` bash
# assumes the venv is activated, see above
pytest
````

A pytest.ini is located in the v2 directory, so that pytest writes out captures to console.

That is useful when working with a single test and is the default:

```` bash
PYTHONPATH=src  pytest -c pytest-minimal.ini tests/test_verbose.py::test_verbose_error_reporting
````

Use to get the minimal info on successful test cases:

```` bash
PYTHONPATH=src pytest -c pytest-minimal.ini
````

or for specific file with test cases:

```` bash
PYTHONPATH=src pytest -c pytest-minimal.ini tests/test_verbose.py
````

### Subprocess coverage (local == CI)

By default, local `pytest` enables subprocess coverage to match the GitHub workflow.
This is done via `COVERAGE_PROCESS_START=pyproject.toml` set in `tests/conftest.py`.

Disable subprocess coverage for a single run:

```` bash
DAR_BACKUP_NO_SUBPROCESS_COVERAGE=1 pytest
````

Or run the full CI-equivalent report flow (same markers + coverage artifacts):

```` bash
./scripts/pytest_report.sh full
````

---

## PyPI download stats

The repo root includes `track_downloads.py` which fetches daily download counts
from the PyPI Stats API and writes `downloads.json` in a time-series format
(similar to `clonepulse/fetch_clones.json`).

Default behavior:

- Re-fetches the last 31 days on each run to catch PyPI corrections.
- Preserves existing `annotations` in `downloads.json`.
- Adds `rollups` (last 7/30 days and averages).
- Adds spike annotations using a rolling median + MAD rule (Hampel-style) with a
  30‑day window, threshold `> 5 * MAD`, and `min_count >= 50`. The MAD is scaled
  by `1.4826` to match the standard deviation for normally distributed data.
  - Auto spike annotations use the label prefix `Spike:` and are regenerated on each run.
  - Manual annotations (any label not starting with `Spike:`) are preserved.
  - If too many spikes appear, increase the MAD threshold or minimum count.

Manual run:

```` bash
cd <path/to/dar-backup>
python track_downloads.py
````

Override the correction window:

```` bash
cd <path/to/dar-backup>
python track_downloads.py --days-back 60
````

The GitHub workflow `update_downloads.yml` runs this on a daily schedule.

References:

```` text
https://en.wikipedia.org/wiki/Median_absolute_deviation
https://en.wikipedia.org/wiki/Hampel_test
https://en.wikipedia.org/wiki/Moving_average
````

---

## Release to PyPI

```bash
cd <path/to/dar-backup/v2>
./release.sh --upload-to-pypi # provide password to GPG to sign the built artifacts
```

---

## Build dar from source

### Check signature

gpg --import \<key\>

Verify source code has not been tampered with:

```bash
gpg --verify dar-2.7.18.tar.gz.sig dar-2.7.18.tar.gz

gpg: Signature made tir 20 maj 2025 18:02:15 CEST
gpg:                using RSA key 55E484A6A5C5BC7F53F7F72EA8B14160D36B3BA7
gpg: Good signature from "Denis Corbin (http://dar.linux.free.fr/) <dar.linux@free.fr>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 1BE4 7606 A74F 178C 7328  43B0 5F64 5B19 16D5 6546
     Subkey fingerprint: 55E4 84A6 A5C5 BC7F 53F7  F72E A8B1 4160 D36B 3BA7
```

### Build

export DAR_VERSION=2.7.21.RC1
This worked for dar version 2.7.21.RC1 on ubuntu 24.04

export SRC_CODE=/some/dir
export DAR_DIR=$HOME/.local/dar-${DAR_VERSION}

```` bash
apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip gettext-base ca-certificates tzdata file gnupg \
      build-essential autoconf automake libtool pkg-config binutils \
      libkrb5-dev libgcrypt-dev libgpgme-dev libext2fs-dev libthreadar-dev \
      librsync-dev libcurl4-gnutls-dev libargon2-dev \
      bzip2 zlib1g-dev libbz2-dev liblzo2-dev liblzma-dev libzstd-dev liblz4-dev \
      groff doxygen graphviz upx
sudo apt-get install libkrb5-dev
sudo apt-get install libgcrypt-dev libgpgme-dev libext2fs-dev  libthreadar-dev  librsync-dev  libcurl4-gnutls-dev
cd "$SRC_CODE"
CXXFLAGS=-O
export CXXFLAGS
make clean distclean
./configure --prefix="$DAR_DIR" LDFLAGS="-lgssapi_krb5"
make
make install-strip

rm $HOME/.local/dar  # remove link
ln -s $HOME/.local/dar-${DAR_VERSION} $HOME/.local/dar
````

---

## Git log

```` bash
git log --pretty=format:"%ad - %an: %s %d" --date=short
````

## Tarball for ChatGPT

```bash
tar --exclude='*/__pycache__' \
  -cvf dar-backup.tar \
  tests/ \
  doc/dev.md \
  doc/doc.md \
  src/  \
  README.md \
  Changelog.md \
  pyproject.toml \
  testall.sh \
  build.sh \
  release.sh \
  pytest.ini  \
  MANIFEST.in \
  pytest-cov.sh \
  pytest.ini \
  requirements-dev.txt
```
