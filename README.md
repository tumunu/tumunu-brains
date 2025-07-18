# Tumunu Brains

A forensic intelligence platform for advanced code analysis and pattern detection.

## Quick Start

```bash
# Build the platform
cargo build --release

# Analyze code samples
./target/release/brains forensics analyze sample.rs --format json

# Classify samples
./target/release/brains forensics classify samples/ --explainable

# Generate forensic report
./target/release/brains report --format markdown --output report.md
```

## Documentation

- [Deployment Guide](docs/deployment.md) - Complete setup and deployment instructions
- [Architecture Overview](docs/architecture.md) - System design and component overview
- [User Guide](docs/user-guide.md) - Command-line interface and API usage
- [Developer Guide](docs/developer-guide.md) - Contributing and extending the platform

## Features

- **Multi-language AST Analysis**: Support for Rust, JavaScript, Python, and more
- **Pattern Detection**: Advanced pattern matching with confidence scoring
- **Provenance Analysis**: Code attribution and fingerprinting capabilities
- **Investigation Sessions**: Persistent analysis sessions with cryptographic signing
- **Forensic Reporting**: Comprehensive reports in multiple formats
- **Surveillance Detection**: Specialized analysis for surveillance artifacts
- **Sample Classification**: Automated classification of code samples

## Architecture

The platform is built as a modular Rust workspace with components for core analysis, pattern detection, AST analysis, provenance tracking, and report generation.

## Security

This platform is designed for defensive security research and follows security best practices for forensic analysis tools.

## License

Apache-2.0 - See LICENSE file for details.