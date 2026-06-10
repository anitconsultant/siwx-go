# Security Policy

## Supported versions
Only the latest tagged release receives security fixes while the project is in v0.x.

## Reporting a vulnerability
Email it@anitconsultant.com with subject "[siwx-go security]". Please include a
proof-of-concept message/signature pair where possible. You will receive an
acknowledgment within 72 hours and a remediation plan or disposition within 14 days.
Please do not open public issues for suspected vulnerabilities before contact.

## Scope
The `siws` and `siwx` packages and their adapters. The `examples/` tree is
demonstration code, explicitly not production-hardened (mock token issuer,
in-memory stores), and is out of scope except where an example flaw implies a
library flaw.

## Disclosure
Coordinated disclosure preferred. Credit given in release notes unless you
request otherwise.
