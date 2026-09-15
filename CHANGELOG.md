# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — unreleased

### Changed
- Restructured flat scripts into an installable `traverse` package with a
  `traverse` console entry point (`pip install -e .`) and `python -m traverse`.
- Target library moved to packaged data (`traverse/data/targets.json`).

### Added
- `pyproject.toml` packaging and a GitHub Actions test workflow (py3.9–3.12).
- Encoding families: 16-bit unicode, UTF-8 overlong, double-encoded null byte
  (`%2500`) with configurable extensions, mangled/dot-truncation, Windows
  drive-letter absolute.
- Categorized target library (poc/secrets/config/cloud/source) with
  `--categories` filtering.
- Injection into POST bodies (`--data`) and JSON bodies (`--json`), plus
  `--method`.
- File-inclusion wrappers: `php://filter` (source disclosure, auto base64
  decode), `data://`, `expect://`, `php://input` (RCE via echoed canary).
- JSON output (`--output json` / `--outfile`) and optional concurrency
  (`--threads`, default 1).

## [0.1.0]

### Added
- Initial path-traversal scanner: bypass engine covering the six PortSwigger
  "File path traversal" labs, baseline-diff detector, data-driven target
  library, auto-discover demo, and offline unit tests.
