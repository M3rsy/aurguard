# Security Policy

AURGuard processes attacker-controlled package metadata, so reports about parser safety, command execution, clone hardening, terminal escape handling, path traversal, symlink handling, or sandbox boundaries are especially important.

## Reporting a vulnerability

Please avoid publishing a working exploit before maintainers have had a reasonable opportunity to assess and fix the issue. Open a private GitHub security advisory when available, or contact the maintainer through the profile information linked from this repository.

Include:

- affected version/commit;
- impact;
- minimal reproduction steps;
- expected vs actual behavior;
- suggested mitigation if known.

AURGuard is a defensive tool and should never claim that a LOW result proves a package is safe.
