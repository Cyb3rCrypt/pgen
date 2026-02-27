# Security Policy

## Supported Versions

Only the latest release receives security fixes. Older versions are not
backported.

| Version | Supported |
|---------|-----------|
| Latest (`1.3.x`) | ✅ |
| Older | ❌ |

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security vulnerabilities.**
Public disclosure before a fix is available puts users at risk.

Use GitHub's built-in private reporting instead:

1. Go to <https://github.com/sharma-vikram/pgen/security/advisories/new>
2. Fill in a brief description, the affected version, and reproduction steps.
3. Submit — only the maintainer can see it.

If you prefer e-mail, reach the maintainer at the address on their
[GitHub profile](https://github.com/sharma-vikram).

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledge receipt | 3 business days |
| Confirm / request more info | 7 business days |
| Publish a fix and CVE (if applicable) | 30 days |

If a fix requires longer than 30 days, the reporter will be notified with
a revised timeline before the deadline.

## Scope

Vulnerabilities in the following are in scope:

- Weak or predictable output from `pgen pass` / `pgen uuid` / `pgen typeid`
- Insecure use of the system CSPRNG (`getrandom`)
- Memory exposure of generated secrets (e.g. heap residue, log output)
- Dependency vulnerabilities that affect the above

Out of scope: build-toolchain issues, GitHub Actions supply-chain items
unrelated to pgen itself, or findings already covered by `cargo audit`.

## Disclosure Policy

Once a fix is released, full details will be published in:

- The GitHub Security Advisory
- The relevant `CHANGELOG.md` entry
