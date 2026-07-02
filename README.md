# CMMC-Scope 🔍

> **Automated CMMC Level 2 / NIST SP 800-171 compliance auditing for cloud and developer environments.**  
> Designed for small-to-midsize defense contractors (DIBs) who need immutable, auditor-ready evidence — fast.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CMMC Level 2](https://img.shields.io/badge/CMMC-Level%202-darkblue.svg)](https://www.acq.osd.mil/cmmc/)

---

## What is CMMC-Scope?

CMMC-Scope is a lightweight, open-source CLI tool that automates the collection
of compliance evidence against specific **CMMC Level 2 (NIST SP 800-171)**
technical controls.  Instead of spending hours manually screenshotting IAM
dashboards and GitHub settings before every audit, you run one command and
receive a signed, timestamped evidence package ready to hand to a C3PAO or
your internal compliance team.

### Phase 1 Controls (this release)

| CMMC Practice ID | NIST 800-171 Ref | Control Family | What is checked |
|---|---|---|---|
| `IA.L2-3.5.3` | §3.5.3 | Identification & Authentication | Every AWS IAM user with console access has MFA enabled |
| `CM.L2-3.4.1` | §3.4.1 | Configuration Management | GitHub repository default branch requires PR review before merge |

---

## Quick Start

### Prerequisites

- Python **3.11** or later
- AWS credentials configured (`~/.aws/credentials`, env vars, or instance profile)
- A GitHub **Personal Access Token** with `repo` scope (or `public_repo` for public repos)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/cmmc-scope.git
cd cmmc-scope

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install the package in editable mode (adds the cmmc-scope console script)
pip install -e .
```

### Run your first audit

```bash
# Check AWS IAM MFA compliance (uses default AWS credential chain)
cmmc-scope audit aws

# Check GitHub branch protection
cmmc-scope audit github --repo your-org/your-repo --token ghp_xxxxxxxxxxxx

# Run all checks and produce a combined report
cmmc-scope audit all --repo your-org/your-repo

# Use a GitHub token from an environment variable
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
cmmc-scope audit all --repo your-org/your-repo --output-dir ./evidence --format pdf
```

---

## CLI Reference

### Top-level

```
cmmc-scope [COMMAND] [OPTIONS]

Commands:
  version        Print tool version and exit.
  audit          Run one or more CMMC compliance checks.
```

### `cmmc-scope audit aws`

Run the **IA.L2-3.5.3** (MFA) check against AWS IAM.

| Option | Default | Description |
|---|---|---|
| `--profile, -p` | *(default chain)* | AWS CLI named profile |
| `--region, -r` | `us-east-1` | AWS region for the boto3 session |
| `--output-dir, -o` | `./cmmc_evidence` | Evidence output directory |
| `--format, -f` | `both` | `json` \| `pdf` \| `both` |
| `--verbose, -v` | `False` | Enable DEBUG logging |

**Exit codes:** `0` = PASS · `2` = FAIL · `3` = collection ERROR

### `cmmc-scope audit github`

Run the **CM.L2-3.4.1** (Branch Protection) check.

| Option | Default | Description |
|---|---|---|
| `--repo` | *(required)* | `owner/repo` e.g. `acme/my-service` |
| `--token, -t` | `$GITHUB_TOKEN` | GitHub Personal Access Token |
| `--branch, -b` | *(repo default)* | Branch to inspect |
| `--output-dir, -o` | `./cmmc_evidence` | Evidence output directory |
| `--format, -f` | `both` | `json` \| `pdf` \| `both` |
| `--verbose, -v` | `False` | Enable DEBUG logging |

### `cmmc-scope audit all`

Run **all** implemented checks and produce a combined evidence package.

Combines options from both `aws` and `github` subcommands (see above).
`--repo` is always required.

---

## Output Artefacts

Each audit run produces timestamped files in `--output-dir`:

```
cmmc_evidence/
├── cmmc_scope_evidence_20240615T143022Z.json   ← Machine-readable evidence
└── cmmc_scope_evidence_20240615T143022Z.pdf    ← Auditor-ready report
```

Both files embed an **SHA-256 integrity hash** of the Finding data so that
any post-generation tampering is detectable by comparing the hash printed on
the cover page to a freshly-computed hash of the JSON payload.

### JSON schema (v1.0)

```json
{
  "schema_version": "1.0",
  "tool": "CMMC-Scope",
  "tool_version": "0.1.0",
  "generated_at_utc": "2024-06-15T14:30:22.000000+00:00",
  "integrity_sha256": "abc123…",
  "summary": { "PASS": 1, "FAIL": 1, "ERROR": 0, "N/A": 0 },
  "findings": [
    {
      "cmmc_practice_id": "IA.L2-3.5.3",
      "nist_control_id": "3.5.3",
      "control_family": "Identification & Authentication (IA)",
      "control_title": "Multi-Factor Authentication for Local and Network Access",
      "status": "FAIL",
      "summary": "2 of 5 IAM users have console access without MFA…",
      "evidence": ["…"],
      "remediation_items": ["…"],
      "evaluated_at": "2024-06-15T14:30:22.000000+00:00",
      "resource_scope": "AWS Account 123456789012"
    }
  ]
}
```

---

## Architecture

```
cmmc-scope/
│
├── cmmc_scope/
│   ├── __init__.py          # Package metadata (__version__, etc.)
│   ├── main.py              # CLI entrypoint — Typer commands, Rich output
│   ├── engine.py            # Compliance brain — pure evaluation logic
│   ├── reporter.py          # Evidence generation — JSON + PDF via fpdf2
│   │
│   └── collectors/
│       ├── __init__.py
│       ├── aws.py           # boto3 — IAM Credential Report
│       └── github.py        # PyGithub — Branch Protection API
│
├── requirements.txt
└── README.md
```

### Design principles

1. **Separation of concerns** — Collectors fetch data. The Engine evaluates it.
   The Reporter writes it. These layers never mix.

2. **Pure evaluation** — `engine.py` contains zero I/O. Every function is
   deterministic and easily unit-tested with mock data.

3. **Immutable findings** — `Finding` and all collector DTOs use frozen
   dataclasses where practical. Once created, evidence objects cannot be mutated.

4. **Fail-safe exit codes** — Non-zero exits on FAIL (`2`) or ERROR (`3`)
   make CMMC-Scope a first-class CI/CD pipeline citizen.

5. **Auditor-legible output** — Every evidence string is written so a human
   (not just a developer) can understand what was checked and why it passed or failed.

---

## CI/CD Integration

CMMC-Scope is designed to be a gate in your GitHub Actions / GitLab CI pipeline.

### GitHub Actions example

```yaml
- name: CMMC Scope — MFA Audit
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AUDIT_AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AUDIT_AWS_SECRET_ACCESS_KEY }}
    GITHUB_TOKEN: ${{ secrets.CMMC_GITHUB_TOKEN }}
  run: |
    pip install -r requirements.txt -e .
    cmmc-scope audit all \
      --repo ${{ github.repository }} \
      --output-dir ./cmmc_evidence \
      --format both

- name: Upload evidence artefacts
  uses: actions/upload-artifact@v4
  with:
    name: cmmc-evidence-${{ github.run_id }}
    path: ./cmmc_evidence/
    retention-days: 2555   # ~7 years — common audit retention requirement
```

---

## Required AWS IAM Permissions

The IAM identity used to run the AWS audit requires the following minimum
permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CMMCScopeIAMRead",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Required GitHub Token Scopes

| Repository visibility | Minimum scope |
|---|---|
| Public | `public_repo` |
| Private (member) | `repo` |
| Private (admin, to read protection rules) | `repo` + admin access on the repo |

For fine-grained PATs: grant **Repository permissions → Administration → Read-only**.

---

## Roadmap

- [ ] **Phase 2** — Additional controls: AC.L2-3.1.1, SC.L2-3.13.8, SI.L2-3.14.1
- [ ] AWS Config + Security Hub integration
- [ ] Azure Active Directory / Entra ID MFA collector
- [ ] OSCAL (Open Security Controls Assessment Language) output format
- [ ] `pyproject.toml` packaging (PEP 517/518)
- [ ] `pytest` test suite with `moto` and `responses` mocks
- [ ] Docker image for air-gapped / container-native environments

---

## Contributing

Contributions are welcome!  Please open an issue first to discuss the change
you'd like to make.  Pull requests should:

- Include unit tests for any new collector or engine logic.
- Pass `ruff check .` and `mypy cmmc_scope/` without errors.
- Follow the existing separation-of-concerns architecture.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Disclaimer

CMMC-Scope automates the *collection of evidence* for specific technical
controls.  It does **not** constitute a formal CMMC assessment, replace a
Certified Third-Party Assessor Organization (C3PAO), or guarantee CMMC
certification.  Always engage a qualified C3PAO for your official assessment.
