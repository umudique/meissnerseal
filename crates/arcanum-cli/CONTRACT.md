# Contract: arcanum-cli

**Version:** 0.1.0
**API Status:** Unstable  
**Spec authority:** MVP-0 scope in docs/architecture/mvp_roadmap.md  
**ADRs:** ADR-008 (encrypted export default)

---

## Public API Surface (CLI commands — MVP-0)

```
arcanum init <PATH>              — create new vault
arcanum add --label L --kind K --vault PATH
                                 — add item (secret value via hidden prompt)
arcanum list <PATH>              — list item IDs and types (no secret values)
arcanum get <item-id> --vault PATH
                                 — retrieve item (secret to stdout after NOTE line)
arcanum export --output PATH --vault PATH
                                 — export encrypted .arcexp bundle
arcanum import --input PATH --vault PATH
                                 — import encrypted .arcexp bundle
arcanum lock                     — lock vault session
```

---

## Planned (post-MVP-0)

```
arcanum import --unsafe-plaintext <PATH>
                                 — import plaintext JSON/CSV (dev/test only)
arcanum transfer create          — create transfer envelope  [MVP-2]
arcanum transfer receive <PATH>  — receive transfer envelope [MVP-2]
arcanum device pair              — pair with another device  [post-MVP-0]
arcanum device list              — list approved devices     [post-MVP-0]
arcanum device revoke <device-id>                            [post-MVP-0]
```

These commands parse correctly but return an error at runtime until wired.

---

## Guarantees

```
[G-01] No plaintext secret values are accepted through command-line arguments
       in production builds.
       Secret input: hidden prompt (rpassword), --stdin flag, or file descriptor.

[G-02] arcanum list and arcanum get --list never print secret field values.
       Only item_id, item_type, and label are shown.

[G-03] arcanum export produces an encrypted .arcexp bundle by default.
       The export passphrase is required and not stored.

[G-04] arcanum import --unsafe-plaintext emits a prominent warning that
       cannot be suppressed and requires explicit acknowledgment.

[G-05] Help text documents shell-history leakage risk.

[G-06] Item retrieval uses opaque item-id, not sensitive item names,
       where practical.
```

---

## Anti-Guarantees

```
[A-01] Does NOT prevent shell history capture of non-secret arguments
       (e.g., item-id, command name).

[A-02] Does NOT prevent the terminal emulator from logging screen output.

[A-03] --unsafe-plaintext mode is documented as unsafe and intended for
       development and test fixture import only.
```

---

## Preconditions

```
[P-01] Vault must exist (arcanum init) before other commands.

[P-02] Export passphrase must be at least 12 characters
       (enforced at prompt, not at API level).
```
