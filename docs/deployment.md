# Deployment Guide

This guide covers the complete setup and deployment of Tumunu Brains for research environments.

## System Requirements

### Hardware
- **CPU**: 4+ cores (8+ recommended for batch processing)
- **RAM**: 8GB minimum (16GB+ for large datasets)
- **Storage**: 20GB+ available space
- **Network**: Internet access for dependency downloads

### Software
- **Rust**: 1.70+ (latest stable recommended)
- **System Libraries**: C compiler, pkg-config, tree-sitter libraries
- **Optional**: Docker for containerized deployment

## Installation

### 1. System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev
```

#### macOS
```bash
brew install pkg-config openssl
```

#### Windows
```powershell
# Install Visual Studio Build Tools
# Install pkg-config via vcpkg or chocolatey
choco install pkgconfiglite
```

### 2. Rust Installation

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update
```

### 3. Platform Build

```bash
# Clone repository
git clone https://github.com/your-org/brains-forensic-platform.git
cd brains-forensic-platform

# Build release binary
cargo build --release

# Verify installation
./target/release/brains --version
```

## Binary Architecture & Operation

The final binary operates as a **defensive forensic analysis platform** with the following architecture:

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│ Input Layer                                                     │
│ - File/Directory Ingestion                                      │
│ - API Endpoints (REST/WebSocket)                                │
│ - CLI Interface                                                 │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Analysis Engine                                                 │
│ - ASTPatternAnalyzer (multi-language support)                  │
│ - ProvenanceFingerprinter (LLM attribution)                    │
│ - FragmentCorrelationEngine (intent reconstruction)            │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Output Layer                                                    │
│ - Cryptographically Signed Reports                             │
│ - JSON/YAML Structured Output                                  │
│ - Audit Logs & Provenance Chain                                │
└─────────────────────────────────────────────────────────────────┘
```

### Operation Flow

1. **Initialization**
   - Loads configuration and pattern databases
   - Initializes language-specific AST parsers
   - Establishes cryptographic signing keys

2. **Input Processing**
   - Accepts code fragments from external sources
   - Validates and preprocesses input files
   - Identifies programming languages automatically

3. **Pattern Analysis**
   - Parses code into Abstract Syntax Trees (AST)
   - Detects suspicious patterns and anomalies
   - Generates confidence scores for each finding

4. **Provenance Attribution**
   - Analyzes token entropy and structural patterns
   - Identifies LLM-specific code signatures
   - Estimates generation timeframes and model families

5. **Fragment Correlation**
   - Correlates patterns across multiple samples
   - Reconstructs potential orchestration patterns
   - Identifies surveillance tool signatures

6. **Report Generation**
   - Produces cryptographically signed forensic reports
   - Maintains complete audit trail
   - Ensures reproducibility for research validation

## Research Workflow Integration

### Important: Code Generation Separation

The binary **does not generate** pseudo-malicious code for safety and compliance reasons. Your research workflow should follow this pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Controlled Code Generation (Separate Environment)       │
│ - Custom scripts/notebooks generate adversarial samples         │
│ - LLM prompts create suspicious code patterns                   │
│ - Sandbox environment ensures safety                           │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Fragment Analysis (Brains Binary)                      │
│ - brains forensics analyze processes generated samples          │
│ - ASTPatternAnalyzer detects patterns in fragments             │
│ - ProvenanceFingerprinter attributes source characteristics     │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Correlation & Reconstruction (Brains Binary)           │
│ - FragmentCorrelationEngine correlates patterns across samples  │
│ - Reconstructs intent graphs and orchestration patterns        │
│ - Identifies surveillance tool signatures                       │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Forensic Reporting (Brains Binary)                     │
│ - Generates signed reports with provenance chain               │
│ - Produces research-grade evidence for publication             │
│ - Maintains audit trail for reproducibility                    │
└─────────────────────────────────────────────────────────────────┘
```

### Example Research Workflow

```bash
# Step 1: Generate adversarial samples (separate environment)
python3 generate_adversarial_samples.py --output ./test_corpus/

# Step 2: Analyze with the final binary
brains forensics analyze \
  --input ./test_corpus/ \
  --recursive \
  --languages rust,javascript,python \
  --output forensic_report.json \
  --signed

# Step 3: Correlate fragments for intent reconstruction
brains forensics correlate \
  --input forensic_report.json \
  --output intent_graph.json

# Step 4: Generate research report
brains report generate \
  --input intent_graph.json \
  --format pdf \
  --output research_findings.pdf
```

## Deployment Options

### 1. Standalone CLI Deployment

```bash
# Install binary to system PATH
sudo cp ./target/release/brains /usr/local/bin/

# Create configuration directory
mkdir -p ~/.config/brains
cp config/default.toml ~/.config/brains/

# Verify installation
brains --version
```

### 2. Server Mode Deployment

```bash
# Start analysis server
brains server start \
  --port 8080 \
  --config ~/.config/brains/server.toml \
  --log-level info

# Test API endpoint
curl http://localhost:8080/api/v1/health
```

### 3. Docker Deployment

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/brains /usr/local/bin/brains
EXPOSE 8080
CMD ["brains", "server", "start", "--port", "8080"]
```

```bash
# Build and run container
docker build -t brains-forensic .
docker run -p 8080:8080 brains-forensic
```

## Configuration

### Environment Variables

```bash
# Logging configuration
export BRAINS_LOG_LEVEL=info
export BRAINS_LOG_FORMAT=json

# Analysis configuration
export BRAINS_MAX_FILE_SIZE=10MB
export BRAINS_ANALYSIS_TIMEOUT=300s

# Server configuration
export BRAINS_SERVER_PORT=8080
export BRAINS_SERVER_HOST=0.0.0.0
```

### Configuration Files

Create `~/.config/brains/config.toml`:

```toml
[analysis]
max_file_size = "10MB"
timeout = "300s"
languages = ["rust", "javascript", "python"]

[server]
port = 8080
host = "0.0.0.0"
max_connections = 100

[logging]
level = "info"
format = "json"
output = "stdout"

[security]
enable_signing = true
key_path = "~/.config/brains/signing.key"
```

## Security Considerations

### 1. Cryptographic Signing

```bash
# Generate signing key
brains keys generate --output ~/.config/brains/signing.key

# Verify report signatures
brains verify --input forensic_report.json --key ~/.config/brains/signing.key
```

### 2. Sandboxing

- Run analysis in isolated environments
- Limit file system access permissions
- Use container isolation for untrusted code analysis

### 3. Audit Logging

```bash
# Enable comprehensive audit logging
export BRAINS_AUDIT_LOG=true
export BRAINS_AUDIT_PATH=/var/log/brains/audit.log
```

## Performance Optimization

### 1. Batch Processing

```bash
# Process multiple files efficiently
brains forensics analyze \
  --input ./large_dataset/ \
  --parallel 8 \
  --batch-size 100 \
  --output results/
```

### 2. Memory Management

```bash
# Configure memory limits
export BRAINS_MAX_MEMORY=8GB
export BRAINS_CLEANUP_INTERVAL=60s
```

### 3. Caching

```bash
# Enable pattern cache
export BRAINS_CACHE_DIR=~/.cache/brains
export BRAINS_CACHE_SIZE=1GB
```

## Troubleshooting

### Common Issues

1. **Build Failures**
   ```bash
   # Update Rust toolchain
   rustup update
   
   # Clean build cache
   cargo clean
   ```

2. **Tree-sitter Errors**
   ```bash
   # Install system dependencies
   sudo apt install -y build-essential
   
   # Rebuild with verbose output
   cargo build --release --verbose
   ```

3. **Permission Errors**
   ```bash
   # Fix file permissions
   chmod +x ./target/release/brains
   
   # Create necessary directories
   mkdir -p ~/.config/brains ~/.cache/brains
   ```

### Debug Mode

```bash
# Enable debug logging
export BRAINS_LOG_LEVEL=debug
export RUST_BACKTRACE=1

# Run with verbose output
brains forensics analyze --input ./test --verbose
```

## Research Compliance

This platform is designed for **defensive forensic analysis only**. It adheres to:

- **Ethical Research Standards**: No malicious code generation
- **Legal Compliance**: Defensive analysis within research guidelines
- **Audit Requirements**: Complete provenance chain for reproducibility
- **Publication Standards**: Cryptographically verifiable results

## Support

For deployment issues or research collaboration:

- Review the [User Guide](user-guide.md) for usage instructions
- Check the [Developer Guide](developer-guide.md) for extension development
- Consult the [Architecture Overview](architecture.md) for system design details