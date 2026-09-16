# mirai-arm64-analysis

Analysis of an ELF/ARM64 sample from the Mirai family.

## Sample

- SHA256: `6c36aaf35baa312a513bfea1afc62293889b9d95937ae8401776383728d36468`
- Architecture: ARM64
- See [samples/hashes.txt](samples/hashes.txt)

## Structure

- `static-analysis/` : disassembly, Ghidra, strings
- `dynamic-analysis/` : sandbox logs, network captures
- `iocs/` : indicators of compromise
- `yara/` : detection rule
- `scripts/` : analysis helper tools
- `docs/report.md` : full report

## Disclaimer

This repo contains no executable malicious binary. Only hashes, notes, analysis code, and IOCs for educational purposes.
