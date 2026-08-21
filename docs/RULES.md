# Built-in rules in v0.1

The v0.1 rules are deliberately deterministic and explainable. Scores will be calibrated against real-world AUR packages before a stable release.

| Rule | Severity | Weight | Signal |
|---|---|---:|---|
| SHELL001 | Critical | 100 | Remote content passed directly to a shell |
| SHELL002 | High | 65 | Dynamic shell evaluation |
| SHELL003 | High | 70 | Privilege escalation in package metadata |
| SHELL004 | High | 65 | Low-level networking utility |
| SHELL005 | Low | 10 | Executable permission added |
| SHELL006 | Low | 10 | Relative executable invocation |
| SHELL007 | Medium | 35 | Base64 decode |
| SHELL008 | High | 60 | Sensitive SSH/GPG/browser credential paths |
| SHELL009 | High | 60 | Sensitive system/process injection paths |
| PKG001 | Low | 10 | Checksum `SKIP` |
| SRC001 | Medium | 20 | Plain HTTP source |
| OBF001 | Medium | 40 | Long Base64-like data |
| NET001 | Medium | 20 | Network downloader in executable metadata |
| PERSIST001 | Medium | 25 | systemd/cron/profile/udev persistence locations |
| FILE001 | High | 70 | ELF magic bundled directly in repository |
| FILE002 | High | 20 | Bundled ELF has executable permission |
| FILE003 | Low | 10 | Symbolic link in repository |

The v0.1 score is additive and capped at 100. Future versions will replace some additive behavior with contextual correlation to reduce false positives.
