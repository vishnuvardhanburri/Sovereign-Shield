# Contributing to Sovereign Shield

Thank you for your interest in contributing to Sovereign Shield! As an open-source enterprise security platform for private AI governance, we welcome contributions from the community while maintaining high security, reliability, and code quality standards required for OpenSSF Silver certification.

---

## Code of Conduct

All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to `security@sovereignshield.org`.

---

## Developer Certificate of Origin (DCO)

To ensure clear licensing and intellectual property governance, all contributions must include a **Developer Certificate of Origin (DCO)** sign-off in every commit message:

```text
Signed-off-by: Jane Doe <jane.doe@example.com>
```

You can automatically add this line to your commits using `git commit -s`.

---

## Security First & Secret Handling

Sovereign Shield is a security platform. We enforce a strict **fail-closed security policy**:

1. **No Embedded Secrets**: Never commit real API keys, private keys, secrets, passwords, or production infrastructure endpoints.
2. **Vulnerability Reporting**: Do **NOT** open public GitHub issues for security vulnerabilities. Follow our [Security Policy](SECURITY.md) and report privately to `security@sovereignshield.org`.
3. **Automated Security Scans**: All PRs run Bandit, Safety SAST scans, and OpenSSF Scorecard checks. PRs with high-severity security findings will be blocked.

---

## Getting Started & Development Setup

### Prerequisites
- Node.js v20+ & `pnpm` v9+
- Python 3.11+ (with `venv`)
- Docker & Docker Compose (optional for containerized tests)

### Local Environment Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/vishnuvardhanburri/Sovereign-Shield.git
   cd Sovereign-Shield
   ```

2. **Backend Setup**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Frontend & Workspace Setup**:
   ```bash
   pnpm install
   ```

4. **Copy Environment Template**:
   ```bash
   cp .env.example .env
   ```

---

## Running Verification & Tests

Before submitting a Pull Request, verify that all local checks pass cleanly:

```bash
# 1. Run Python Backend Unit & Security Tests
PYTHONPATH=backend pytest tests/ -v

# 2. Run Policy YAML Validation
python3 -c "import yaml, os; [yaml.safe_load(open(os.path.join(r, f))) for r, _, fs in os.walk('presets') for f in fs if f.endswith('.yaml')]"

# 3. Run Cross-Platform Doctor
PYTHONPATH=backend python3 scripts/cross_platform_doctor.py

# 4. Run TypeScript & Workspace Check
pnpm cross:check
pnpm --filter @sovereign-shield/web check

# 5. Run Static Frontend & Production Build
pnpm build
```

---

## Pull Request Workflow

1. **Branch Naming**:
   - Features: `feat/short-description`
   - Fixes: `fix/short-description`
   - Security: `sec/short-description`
   - Documentation: `docs/short-description`

2. **Commit Messages**:
   - Use conventional commit messages: `feat: add DPDP Act consent validator`, `fix: update rate limiter bucket window`.
   - Always sign off commits (`git commit -s`).

3. **Code Review & Approval**:
   - Every PR requires at least **one approving review** from a core maintainer.
   - All GitHub Actions CI checks (backend tests, frontend build, cross-platform check, scorecard scan) must pass before merging.

---

## License

By contributing to Sovereign Shield, you agree that your contributions will be licensed under the project's [Apache 2.0 License](LICENSE).
