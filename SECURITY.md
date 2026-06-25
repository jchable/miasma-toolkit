# Security Policy

This is a **defensive** incident-response toolkit (detection + remediation) for the Miasma /
Shai-Hulud worm and CVE-2026-35603. It ships no network service and, by design, the scanner and
YARA rules are **read-only**. The only components that modify the filesystem are the optional
Claude Code hooks under `.claude/`, which *move* infected files to a reversible, git-ignored
quarantine vault (never hard-delete).

## Supported versions

Only the latest commit on `main` is supported. Indicators (`iocs.psd1`) are expected to evolve as
new worm variants appear — pin a commit if you need reproducibility.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an undisclosed
vulnerability.

- Preferred: open a [GitHub private security advisory](https://github.com/jchable/miasma-toolkit/security/advisories/new).
- Alternative: contact the maintainer through their GitHub profile.

When reporting, include where possible:

- the affected file and version (commit hash),
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested fix.

Please allow a reasonable time for a fix before public disclosure.

## What counts as a security issue here

Because this is detection tooling, the security-relevant bug classes are specific:

- **False negatives** — a known Miasma/Shai-Hulud artifact or behavior that the scanner, YARA
  rules, or hooks fail to flag.
- **Detection bypass** — an input that evades `iocs.psd1` matching or the `.claude/` guard hooks.
- **Unsafe behavior** — anything that causes the read-only tools to write/execute, the hooks to
  delete (rather than quarantine) data, or `purge-history.sh` to act without its backup/guard.
- **Self-quarantine / self-block regressions** — the hooks wrongly acting on the toolkit's own
  files (see `Test-MiasmaExcluded`).

New indicators for emerging variants are very welcome — open a normal PR against `iocs.psd1`
(see [CONTRIBUTING.md](CONTRIBUTING.md)); these are not treated as private security reports.

## Safe-handling note

The `content/` incident reports and several toolkit files contain real **indicator strings**
(`.github/setup.js`, loader signatures, etc.) on purpose. They are inert documentation/data — but
treat any *actual* dropper or payload you collect during an investigation as live malware: analyze
it in an isolated environment and never execute it.
