# Security Policy

## Supported Versions

Security fixes are applied to the latest minor release only.

| Version | Supported |
| ------- | --------- |
| 1.33.x  | ✅        |
| < 1.33  | ❌        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use one of the following channels:

### GitHub Private Vulnerability Reporting (preferred)

Go to **Security → Report a vulnerability** on this repository. GitHub keeps the report private until a fix is released.

### Email

Send a report to **cristianjelovcic@gmail.com** with subject `[SECURITY] gentle-ai <brief description>`.

Include:
- Description of the vulnerability and its impact
- Steps to reproduce or proof-of-concept
- Affected versions
- Any suggested mitigations

## Response SLA

| Stage | Target |
|-------|--------|
| Acknowledgement | 72 hours |
| Severity assessment | 5 business days |
| Fix for Critical/High | 14 days |
| Fix for Medium | 30 days |
| Fix for Low | 90 days |

## Coordinated Disclosure

We follow a **90-day coordinated disclosure** policy. We ask that you do not publish details of the vulnerability until a fix is available and users have had reasonable time to update. We will credit reporters in the release notes unless anonymity is requested.

## Scope

**In scope:**

- `scripts/install.sh` and `scripts/install.ps1` — remote code execution surface
- Auto-update mechanism (`internal/update/`) — binary replacement without verification
- Configuration file handling — path traversal, injection, privilege escalation
- MCP server configuration — unauthorized server injection
- Credential or token handling in any component

**Out of scope:**

- Skills contributed by the community (`.claude/skills/`, third-party skill repos)
- Third-party MCP servers configured by the user
- Issues in upstream dependencies (report directly to those projects)
- Social engineering attacks

## Binary Verification

Starting from v1.34.0, all release binaries are signed with [cosign](https://docs.sigstore.dev) keyless OIDC signing. To verify a release manually:

```bash
cosign verify-blob \
  --certificate-identity-regexp "^https://github.com/Gentleman-Programming/gentle-ai/.github/workflows/release.yaml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

Download `checksums.txt`, `checksums.txt.pem`, and `checksums.txt.sig` from the GitHub Releases page.
