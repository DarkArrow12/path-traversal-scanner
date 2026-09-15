# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — unreleased

### Changed
- Restructured flat scripts into an installable `traverse` package with a
  `traverse` console entry point (`pip install -e .`) and `python -m traverse`.
- Target library moved to packaged data (`traverse/data/targets.json`).

### Added
- `pyproject.toml` packaging and a GitHub Actions test workflow.

_(Further 0.2.0 entries — expanded encoding dictionary, categorized target
library, POST/JSON injection, JSON output, file-inclusion wrappers — added as
they land.)_

## [0.1.0]

### Added
- Initial path-traversal scanner: bypass engine covering the six PortSwigger
  "File path traversal" labs, baseline-diff detector, data-driven target
  library, auto-discover demo, and offline unit tests.
