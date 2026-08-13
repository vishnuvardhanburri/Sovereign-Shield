# Project Governance & Maintainership

Sovereign Shield operates under an **Open Governance model** adhering to OpenSSF (Open Source Security Foundation) Silver Level standards. We prioritize security, transparency, vendor-neutral decision making, and community-driven development.

---

## Governance Roles

### 1. Contributors
Anyone who submits code, documentation, security research, policy presets, or bug reports to Sovereign Shield is a Contributor.
- **Requirements**: Sign DCO (`git commit -s`), follow Code of Conduct.
- **Privileges**: Submit PRs, join community discussions, report issues.

### 2. Maintainers
Maintainers are trusted community members responsible for code review, release management, security triage, and technical direction.
- **Responsibilities**:
  - Triage issues and review Pull Requests (minimum 1 approval required for merge).
  - Enforce security standards, dependency upgrades, and test coverage (>80%).
  - Participate in security vulnerability response team (24h SLA).
- **Current Maintainers**:
  - Vishnu Vardhan Burri (`@vishnuvardhanburri`) - Project Lead & Architect
  - Xavira Tech Labs Core Security Team (`security@xaviratech.com`)

---

## Decision-Making Process

1. **Lazy Consensus**: Normal technical improvements, bug fixes, documentation updates, and standard PR approvals operate on lazy consensus. If a PR has passed all automated CI checks and has 1 Maintainer approval with no open objections for 48 hours, it may be merged.
2. **Consensus Seeking**: Significant architecture changes, new security modules, database schema breaking changes, or policy engine refactors require consensus among Maintainers.
3. **Voting**: If consensus cannot be reached on a strategic decision:
   - Each Maintainer gets 1 vote.
   - Motions pass with a simple majority (>50%).
   - Security-critical decisions affecting fail-closed behavior require a 2/3 supermajority.

---

## Maintainer Onboarding & Offboarding

### Becoming a Maintainer
Contributors who consistently demonstrate high-quality code contributions, thorough security reviews, and positive community leadership over at least 3 months may be nominated by an existing Maintainer. Nomination passes upon 2/3 Maintainer approval.

### Offboarding / Emeritus Status
Maintainers who become inactive for over 6 months without notice may be moved to Emeritus Maintainer status to ensure security keys, merge privileges, and release authority remain active and secure.

---

## Transparency & Open Meetings

All project discussions, architectural decision records (ADRs), roadmap planning, and issue tracking occur publicly on GitHub. Security-sensitive vulnerability reports are handled confidentially until a coordinated patch is released.
