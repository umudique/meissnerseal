# Arcanum Security Lab

**Status:** Skeleton — activates after MVP-2

The security lab is a controlled environment for conducting, observing, and
documenting adversarial tests against the Arcanum implementation.
Every test is a scientific observation: hypothesis, method, result, conclusion.

---

## Activation Criteria

The lab activates when:
- MVP-2 (Transfer Protocol) is complete and stable
- arcanum-crypto and arcanum-pqc pass all static tools and Miri
- A QEMU environment with the built binary can be provisioned

Before MVP-2, this directory holds the scenario templates only.

---

## Directory Structure

```
security-lab/
  README.md               — this file
  environment/
    QEMU-setup.md         — VM provisioning and configuration
    GDB-procedures.md     — GDB commands for memory and runtime analysis
    tooling.md            — required tools and versions
  scenarios/
    README.md             — scenario format specification
    001-*.md through 010-*.md
  results/
    README.md             — results format
    [scenario-id]_[YYYY-MM-DD]_[outcome].md
```

---

## Scenario Outcome Values

```
EXPECTED     — system behaved as documented
ANOMALY      — unexpected behavior observed; requires investigation
CONFIRMED    — vulnerability confirmed; blocker
INCONCLUSIVE — insufficient evidence; retry with different methodology
```

---

## Rules

- Never use real secret values in lab scenarios
- Lab results are scientific observations, not marketing claims
- A CONFIRMED outcome is a release blocker
- All scenarios must be reproducible from the documented method
