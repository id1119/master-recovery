# Archived SSS research

This directory retains research documents from the `sss-hardening` branch for
historical review. Its hand-written Python cryptographic implementation, tests,
package metadata, and API contract were removed from the final repository on
2026-08-15 because they were not used by Master Recovery and violated the
project rule against custom cryptographic primitives.

Nothing under this directory is an implemented or audited Master Recovery
protocol. The final threshold-sharing architecture, branch disposition, tests,
benchmarks, and non-claims are recorded in [`../SHAMIR_AUDIT.md`](../SHAMIR_AUDIT.md).
