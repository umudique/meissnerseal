# Scenario Format

Each scenario file follows this structure:

```markdown
# [ID]: [Title]

**Status:** Pending / In Progress / Complete
**Phase:** MVP-2 / MVP-3 / Beta / Production
**Threat model ref:** [adversary and threat from specs/security/threat_model.md]
**Spec ref:** [relevant spec section]

## Hypothesis
What the scenario expects to observe based on the design.

## Method
Step-by-step procedure. Tools, commands, environment settings.

## Success Criteria
What constitutes expected (passing) behavior.

## Failure Criteria
What constitutes a security failure requiring investigation.

## Observations
[Filled in after execution]

## Outcome
EXPECTED / ANOMALY / CONFIRMED / INCONCLUSIVE

## Evidence
Log files, GDB output, memory dumps (redacted of any real secret data).

## Conclusion
What was learned. Any follow-up required.
```
