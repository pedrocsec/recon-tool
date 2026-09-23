# Changelog

All notable changes to Recon Tool are documented in this file.

The project is under active development, so future releases may introduce
changes to functionality, output formats, and internal modules.

## [4.1.3] - 2026-09-22

### Added

- NVD API integration for CVE correlation.
- Optional NVD API key support through the `NVD_API_KEY` environment variable.
- Structured JSON output for reconnaissance results.
- HTTP-based technology detection using collected evidence.
- CPE-based correlation between detected technologies and NVD vulnerability data.

### Improved

- CVE correlation logic now validates whether the NVD configuration
  actually applies to the identified CPE.
- Reduced potential false-positive CVE correlations.
- Improved handling of CVE correlation data and results.
- Updated project documentation for the current release.

### Security

- NVD API credentials are read from an environment variable and are not
  intended to be stored in source code.
- Generated reconnaissance data and local cache files are excluded from
  version control.

## [4.1.2]

Initial stable version documented in the repository history.

---

## Development

Recon Tool is actively developed as a cybersecurity learning project.
Future releases may change existing behavior, output structures, and
internal implementation details.
