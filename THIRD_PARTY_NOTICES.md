# Third-Party Notices & License Compliance

`ai-sbom-gate` is licensed under **Apache-2.0** and is built to pass its own strict compliance gate with **zero mandatory third-party runtime dependencies**.

## Runtime Dependencies

* **Core Engine (`src/ai_sbom_gate/`)**: Uses only the Python Standard Library (PSF-2.0 License).
* **Built-in SPDX Catalog**: Derived from standard public SPDX license identifiers (CC0-1.0 / public metadata).

## Optional Extras

| Component | Package | License | Purpose |
| :--- | :--- | :--- | :--- |
| Test Suite | `pytest` (`>=7.0`) | MIT | Development and CI unit/integration tests |
| YAML Parser | `PyYAML` (`>=6.0`) | MIT | Optional full YAML parsing for `environment.yml` / config files (falls back to built-in line parser when absent) |
