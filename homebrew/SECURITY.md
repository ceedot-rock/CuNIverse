# Security Policy

This tap ships installable software. A security issue here is anything that
could make a user's machine install or run something other than what the
formula claims: a hijacked or mismatched `url`, a `sha256` that does not match
the upstream release, a tampered dependency, or malicious code in the formula
itself.

## Reporting a vulnerability

Please do not open a public issue for security problems.

- Use GitHub's private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability"), or
- Email: corey@slidphilabs.com with the subject line `homebrew-cuni security`

Include the affected formula file and line, what you expected versus what you
observed (e.g. the tarball's actual sha256 vs the formula's), and any steps to
reproduce.

You can expect an acknowledgement within 3 business days. We will keep you
updated while we investigate and credit you in the changelog unless you prefer
to stay anonymous.

## Out of scope

- Vulnerabilities in the CuNi software itself — report those to the
  github.com/ceedot-rock/cuni repository.
- Social engineering, spam, or denial-of-service against mirrors or registries
  we do not run.
