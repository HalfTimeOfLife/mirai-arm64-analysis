# Analysis Report

## Summary

- SHA256: **6c36aaf35baa312a513bfea1afc62293889b9d95937ae8401776383728d36468**
- Architecture: ARM64 (AArch64)
- Family: Gafgyt/Mirai (Linux DDoS botnet)

## 1. Static triage

I began by using commands to have a first view of the malware :

- `file samples/6c36aaf.../6c36aaf<...>.elf`:

```bash
samples/6c36aaf.../6c36aaf<...>.elf: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
```

- `stat -c '%s bytes' samples/6c36aaf.../6c36aaf<...>.elf`

```bash
197488 bytes
```

- `readelf -h samples/6c36aaf.../6c36aaf<...>.elf`:

```bash
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x4004e0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          196784 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         3
  Size of section headers:           64 (bytes)
  Number of section headers:         11
  Section header string table index: 10
```

- `readelf -S samples/6c36aaf.../6c36aaf<...>.elf`:

```bash
There are 11 section headers, starting at offset 0x300b0:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .init             PROGBITS         0000000000400120  00000120
       0000000000000010  0000000000000000  AX       0     0     4
  [ 2] .text             PROGBITS         0000000000400140  00000140
       000000000001d290  0000000000000000  AX       0     0     32
  [ 3] .fini             PROGBITS         000000000041d3d0  0001d3d0
       0000000000000010  0000000000000000  AX       0     0     4
  [ 4] .rodata           PROGBITS         000000000041d3e0  0001d3e0
       000000000000361a  0000000000000000   A       0     0     16
  [ 5] .init_array       INIT_ARRAY       000000000043ff78  0002ff78
       0000000000000008  0000000000000008  WA       0     0     8
  [ 6] .fini_array       FINI_ARRAY       000000000043ff80  0002ff80
       0000000000000008  0000000000000008  WA       0     0     8
  [ 7] .got              PROGBITS         000000000043ff88  0002ff88
       0000000000000060  0000000000000008  WA       0     0     8
  [ 8] .data             PROGBITS         0000000000440000  00030000
       0000000000000060  0000000000000000  WA       0     0     16
  [ 9] .bss              NOBITS           0000000000440060  00030060
       00000000004298e0  0000000000000000  WA       0     0     16
  [10] .shstrtab         STRTAB           0000000000000000  00030060
       000000000000004d  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)
```

- `readelf -d samples/6c36aaf.../6c36aaf<...>.elf`:

```bash
There is no dynamic section in this file.
```

- `grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' static-analysis/strings/strings_ascii.txt | sort -u`

```bash
127.0.0.1
```

- `grep -Ei '!(udp|syn|ack|holdit|junk|tcp|std|http|greip|greeth|stomp)' static-analysis/strings/strings_ascii.txt`

```bash
!udpcustom
!udpplain
```

- `grep -Ei 'bot_lock|watchdog|/proc/|/tmp/|crontab|resolv.conf' static-analysis/strings/strings_ascii.txt`

```bash
/proc/self/exe
/proc/net/tcp
/proc/%s/cmdline
/proc/%s/comm
watchdog
/proc/%s/exe
/proc/%s/status
/proc/%s/fd/
/proc/
/tmp/.bot_lock
/etc/resolv.conf
/proc/se
```

- `strings -n 6 sample.elf > static-analysis\strings\strings_ascii.txt`

Find the result of this command in the file [static-analysis\strings\strings_ascii.txt](../static-analysis\strings\strings_ascii.txt).

- `strings -n 6 -e l sample.elf > static-analysis\strings\strings_utf16le.txt`

Find the result of this command in the file [static-analysis\strings\strings_utf16le.txt](../static-analysis\strings\strings_utf16le.txt).

- `aarch64-linux-gnu-objdump -d -j .text samples/6c36aaf.../6c36aaf....elf > static-analysis/disasm/objdump_text.txt`

Find the result of this command in the file [static-analysis\disasm\objdump_text.txt](../static-analysis\disasm\objdump_text.txt).

## 2. Deep static analysis

## 3. Dynamic analysis

## 4. IOCs

## 5. Detection (YARA)

## 6. Conclusion
