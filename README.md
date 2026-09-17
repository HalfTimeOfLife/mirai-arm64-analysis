# mirai-arm64-analysis

Analysis of an ELF/ARM64 sample from the Mirai/Gafgyt family.

---

## Sample

- SHA256: `6c36aaf35baa312a513bfea1afc62293889b9d95937ae8401776383728d36468`
- Architecture: ARM64 (AArch64)
- See [samples/hashes.txt](samples/hashes.txt)

---

## Status

| Stage                     | Status         |
|---------------------------|----------------|
| Triage & basic analysis   | ✅ Done         |
| Static analysis           | ✅ Done         |
| Dynamic analysis          | ⬜ Not started  |
| YARA rule                 | ⬜ Not started  |
| PoC scripts               | 🔶 In progress |

---

## Tools

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.0.3
- [GhidraMAT](https://github.com/HalfTimeOfLife/GhidraMAT) v1.0

---

## Structure

```text
mirai-arm64-analysis/
├── docs
│   ├── images
│   │   ├── entropy.png
│   │   ├── file_lock.PNG
│   │   ├── ghidramat_panel_findings_anti_vm.PNG
│   │   └── ghidramat_panel_findings_crypto.PNG
│   ├── 0_triage_and_basic_analysis.md
│   ├── 1_static_analysis.md
│   └── README.md
├── dynamic-analysis
│   ├── network-captures
│   ├── sandbox-logs
│   └── syscalls
├── iocs
│   └── iocs.csv
├── poc
│   ├── command-dispatch
│   │   └── README.md
│   ├── decrypt_with_hex_key
│   │   ├── README.md
│   │   └── decrypt.py
│   └── README.md
├── samples
├── static-analysis
│   ├── disasm
│   │   ├── objdump_rodata.txt
│   │   └── objdump_text.txt
│   ├── ghidra
│   │   └── 6c36aaf35baa312a513bfea1afc62293889b9d95937ae8401776383728d36468.elf.gzf
│   ├── strings
│   │   ├── strings_ascii.txt
│   │   └── strings_utf16le.txt
│   └── README.md
├── .gitignore
├── LICENSE
└── README.md
```

---

## Documentation

- [0. Triage and Basic Analysis](docs/0_triage_and_basic_analysis.md): Initial sample identification, ELF headers, section layout, strings extraction.
- [1. Static Analysis](docs/1_static_analysis.md): Static reverse engineering, main execution flow, state machine, identified functions.

---

## Disclaimer

This repository does not contain the raw/original malicious binary (see [.gitignore](.gitignore), only `samples/hashes.txt` and `samples/README.md` are versioned).

The Ghidra project archive in [static-analysis/ghidra/](static-analysis/ghidra/) is an annotated analysis database (renamed functions/variables, comments) built from the sample during reverse engineering. This file technically retains the sample's program data in a serialized/compressed form; it is not a clean copy of the malware as originally distributed.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.