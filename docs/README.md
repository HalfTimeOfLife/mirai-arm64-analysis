# docs/

Documentation of the static and dynamic analysis of an ARM64 ELF sample from the Mirai/Gafgyt family.

---

## Documentation

### 0. Triage and Basic Analysis

Initial sample identification, ELF headers, section layout, strings extraction, and basic binary information.

[Read the triage and basic analysis](0_triage_and_basic_analysis.md)

### 1. Static Analysis

Static reverse engineering of the malware, including the main execution flow, state machine, and identified functions.

[Read the static analysis](1_static_analysis.md)

---

## Images

Screenshots and visual artifacts produced during the analysis.

- [Entropy analysis](images/entropy.png) - Entropy analysis.
- [File locking behavior](images/file_lock.PNG) - File locking behavior.
- [GhidraMAT anti-VM findings](images/ghidramat_panel_findings_anti_vm.PNG) - GhidraMAT anti-VM findings.
- [GhidraMAT cryptographic findings](images/ghidramat_panel_findings_crypto.PNG) - GhidraMAT cryptographic findings.

---

## Table of Contents

| Section | Description |
| ------- | ----------- |
| [0. Triage and Basic Analysis](0_triage_and_basic_analysis.md) | Initial sample identification and basic static analysis |
| [1. Static Analysis](1_static_analysis.md) | Static reverse engineering and malware behavior analysis |
| [Images](#images) | Screenshots and visual artifacts |