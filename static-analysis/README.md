# static-analysis/

Raw output of the static analysis phase (see [docs/1_static_analysis.md](../docs/1_static_analysis.md) for the write-up).

- [`ghidra/`](ghidra/): Annotated Ghidra project archive (`.gzf`): renamed functions/variables and comments added during reverse engineering.
- [`disasm/`](disasm/): `objdump` disassembly of the `.text` and `.rodata` sections.
- [`strings/`](strings/): Extracted ASCII and UTF-16LE strings from the binary.