# Arcanum Security Incident Response

**Status:** Draft — complete before MVP-5 (Managed Sync Beta)

---

## 1. Severity Classification

| Severity | Definition | Response Time |
|---|---|---|
| Critical | Plaintext secret exposure or vault key compromise | < 4 hours |
| High | Protocol flaw or authentication bypass | < 24 hours |
| Medium | Information leakage without direct key compromise | < 72 hours |
| Low | Non-security defect or hardening improvement | < 2 weeks |

---

## 2. Triage Process

1. Receive report via SECURITY.md contact channel
2. Assign severity within 48 hours
3. Reproduce the issue in isolated environment
4. Identify affected versions and components
5. Determine if vault files, keys, or plaintext are at risk

---

## 3. Response Steps

**Critical/High:**
1. Notify core maintainers immediately
2. Disable affected managed service features if applicable
3. Prepare patch in private branch
4. Prepare CVE request if applicable
5. Coordinate 90-day disclosure window with reporter
6. Release patch + signed artifacts
7. Publish advisory

**Medium/Low:**
1. Acknowledge report
2. Schedule fix in normal release cycle
3. Credit reporter in changelog (with permission)

---

## 4. Managed Service Specifics

- Operational logs must never contain secrets (verify before any log review)
- Support tooling has no plaintext vault access (verify before any support action)
- Any breach of encrypted blob storage is treated as Critical even if blobs are opaque

---

## 5. Communication

- Do not discuss unreleased vulnerabilities in public issues or PRs
- Use encrypted email or Signal for sensitive coordination
- Publish post-mortems for Critical incidents after resolution
