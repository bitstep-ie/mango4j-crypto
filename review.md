# Code and security review

Static review of the aggregator/parent POM, its module declarations, inherited plugins and the Checkstyle setup. The POM has no production code. Dependencies and plugins were not scanned for known vulnerabilities.

## Findings

1. **Build tooling versions differ between parent POMs** (Low). This parent uses Checkstyle 10.26.1 while `mango4j-spring-parent` uses 14.3.0, so the two trees enforce different rule sets.

2. **The `hammer-time` profile no longer states the enforced thresholds** (Low). The profile defaults to 100% mutation and coverage, but `mango4j-crypto-core` (98/99) and `mango4j-crypto` (99/100) override them in their own POMs to the current scores. The profile's description therefore overstates the gate.

## Notes

- The `release` profile makes GPG signing opt-in; release automation should select and verify it explicitly.
