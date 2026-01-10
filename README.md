#  Havik

**Havik** is a modular CLI tool designed to scan and analyze security configurations in public cloud environments. It currently supports AWS, Azure and GCP. The tool helps identify weak spots such as missing encryption, overly permissive access, and insecure IAM policies — especially where native tools like AWS Security Hub fall short. The tool generates reports in CLI, JSON and HTML. It also maps the configurations to CSA CCM controls.

## Features

- Encryption checks (S3, DynamoDB/GCS buckets)
- Public access detection
- IAM policy analysis using LLMs (for AWS services)
- Output in human-readable tables or JSON and HTML
- Modular structure, ready to scale across clouds and services
- Maps to CSA CCM controls

## Installation

You can install locally using Python:

```bash
git clone https://github.com/mindhive-security/havik.git
cd havik
python -m pip install .
```

> **Note**: `pyproject.toml` and dependency management included. PyPI packaging is planned.

## Quick Start

### Usage

```bash
havik -h
```

### AWS S3

```bash
havik aws s3 # Checks s3 security configuration
havik aws s3 --json # JSON output
havik aws s3 --html # HTML output
havik aws s3 --no-ai # Do not use features based on LLM
```

### GCP Storage

```bash
havik gcp storage # Security configuration of GCP bucket
```

### Azure Storage Account

```bash
havik az storage # Security configuration of Azure storage account
```

### Reporting

With --html flag the report is produced locally in html/reports/index.html. This report contains all information about the resource configuration and provides mapping to CSA Cloud Controls Matrix (CCM) controls. Later this feature will be extended to generic DORA paragraphs and other regulations articles. This mapping will be done on best approach combining static mapping and LLM evaluation.

### AI-Assisted IAM Policy Evaluation (Optional)

This tool can evaluate bucket IAM policies using a local LLM (e.g., Mistral) for heuristic risk analysis. This feature is **optional** and currenty only works if:

1. You have a locally running LLM (tested with [Ollama](https://ollama.com/) and [Mistral](https://mistral.ai/)).
2. The `LLM_HOST` environment variable is set to point to your local LLM server (default: `http://localhost:11434`).

#### Example setup

```bash
ollama run mistral
export LLM_HOST=http://localhost:11434
```

## Roadmap

- ✅ AWS S3: encryption, public access, IAM analysis
- ✅ AWS DynamoDB: encryption, IAM analysis
- ✅ GCP Storage: encryption, public access
- ✅ Azure Storage Account: encryption
- ⏳ Resource inventory module
- ⏳ Threat intelligence: toxic IAM combinations
- ⏳ Plugin support per cloud/service
- ⏳ Web interface or full SaaS version

## Project Structure

```
src/havik/
├── aws/           # AWS-specific scanners
├── gcp/           # GCP-specific scanners
├── az/            # Azure-specific scanners
├── cli.py         # CLI entry point
```

> Note: Output handling is currently mixed with logic — planned refactor will separate concerns.

## License

Apache License 2.0 - you can use the software for any purpose.

---

## Contributing

This is an early-stage project. All contributions, issue reports, and suggestions are welcome!

---

## Vision

Havik Scanner aims to be a vendor-agnostic, open-source solution that complements native cloud security tooling — especially for European companies with strong compliance needs.
