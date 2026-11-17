# Contributing to AI-SBOM-Gate

Thank you for helping make AI supply chains transparent and license-compliant!

## Local Development

```bash
PYTHONPATH=src python -m pytest tests/ -v
PYTHONPATH=src python -m ai_sbom_gate.cli scan . --exclude examples --policy open-source-permissive
```

## Adding a New License Rule or Permissive Alternative

1. Add the normalized SPDX / custom AI license profile in `src/ai_sbom_gate/catalog/spdx_licenses.py`.
2. Add well-known Hugging Face models/datasets or PyPI/npm packages in `src/ai_sbom_gate/catalog/known_assets.py`.
3. Add verified permissive replacements in `src/ai_sbom_gate/catalog/alternatives.py`.
4. Add unit tests in `tests/test_spdx_and_policy.py` verifying behavior across all four policy modes.
