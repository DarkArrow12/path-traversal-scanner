# Roadmap & known limitations

Tracked here so improvements found during real use aren't lost. Most of the items
below surfaced dogfooding `traverse` against a live target (OWASP Juice Shop `/ftp`,
2026-09-16), where the confirmation logic proved too trusting.

## Known limitations (fix first — these hurt real usage)

1. **False positives on error pages.** The detector will report `HIGH` on an
   application's own error/block page (e.g. a `403` "only .md/.pdf allowed") when the
   response happens to satisfy the signature. It has no notion of a *negative* page.
   - Root cause seen: a catch-all signature (`.`, which matches any character) forced a
     HIGH on the block page, and `stop_on_first` then aborted before the real payload ran.
   - Fix: (a) reject/warn on trivially-broad signatures; (b) treat the learned failure
     baseline (and repeated identical error bodies) as negative even under a signature hit.

2. **No confirmation path for binary / unknown-content files.** `HIGH` requires a text
   signature, so binaries (e.g. a `.kdbx` vault) can't be confirmed and users are pushed
   toward bad signatures.
   - Fix: add `--not-signature REGEX` (negative match — hit only if the block text is
     ABSENT) and content-type / size-divergence confirmation for non-text targets.

3. **SPA noise → false MEDIUM.** Single-page apps return `200` + `index.html` for almost
   any path; the baseline-divergence heuristic then flags a wall of MEDIUMs.
   - Fix: fingerprint the SPA/index-html baseline (size/words) and suppress matches to it.

4. **No discovery — assumes recon is already done.** The tool exploits a known file at a
   known point; it doesn't learn the filter or find files. In practice the target-specific
   inputs (filename, allowed extensions) come from separate recon.
   - Fix: (a) auto-learn the extension allowlist from the block-page error and set
     `--null-exts` automatically; (b) a backup/sensitive-filename wordlist mode; (c) a
     directory-listing enumeration helper.

## Planned improvements (nice-to-have, after the above)

- Structured findings export tuned to drop straight into a pentest report (severity, CWE).
- Recon-to-findings feed: consume an nmap/ffuf result and pick targets automatically.
- Rate-limit / lockout awareness before any noisy sweep.

## Notes
- Private design docs (`PLAN.md`, `SPEC.md`) are git-ignored and stay out of this repo.
