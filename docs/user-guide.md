# User Guide

Complete guide for using the Brains Forensic Platform for code analysis and research.

## Getting Started

### Installation Verification

```bash
# Check installation
brains --version

# View available commands
brains --help
```

### Basic Usage

```bash
# Analyze a single file
brains forensics analyze --input example.rs

# Analyze a directory
brains forensics analyze --input ./src --recursive

# Generate detailed report
brains forensics analyze --input ./samples --output report.json --verbose
```

## Command Reference

### Core Commands

#### `brains forensics analyze`

Perform forensic analysis on source code files.

**Basic Syntax:**
```bash
brains forensics analyze [OPTIONS] --input <PATH>
```

**Options:**
- `--input <PATH>` - Input file or directory path
- `--output <FILE>` - Output report file (default: stdout)
- `--recursive` - Process directories recursively
- `--languages <LANG>` - Comma-separated language list (rust,javascript,python)
- `--signed` - Generate cryptographically signed report
- `--verbose` - Enable verbose output
- `--parallel <N>` - Number of parallel workers (default: CPU count)
- `--timeout <SECONDS>` - Analysis timeout per file (default: 300)

**Examples:**
```bash
# Analyze Rust project
brains forensics analyze --input ./my-project --languages rust --recursive

# Multi-language analysis with signing
brains forensics analyze \
  --input ./mixed-codebase \
  --languages rust,javascript,python \
  --signed \
  --output forensic-report.json

# Batch processing with custom settings
brains forensics analyze \
  --input ./large-dataset \
  --parallel 8 \
  --timeout 600 \
  --output results/
```

#### `brains forensics correlate`

Correlate code fragments to reconstruct intent patterns.

**Basic Syntax:**
```bash
brains forensics correlate [OPTIONS] --input <REPORT>
```

**Options:**
- `--input <REPORT>` - Input forensic report file
- `--output <FILE>` - Output correlation results
- `--threshold <FLOAT>` - Correlation threshold (0.0-1.0, default: 0.7)
- `--intent-reconstruction` - Enable intent graph reconstruction
- `--orchestration-detection` - Detect orchestration patterns

**Examples:**
```bash
# Basic correlation
brains forensics correlate --input forensic-report.json

# Advanced correlation with intent reconstruction
brains forensics correlate \
  --input forensic-report.json \
  --intent-reconstruction \
  --orchestration-detection \
  --output correlation-results.json
```

#### `brains memory`

Manage analysis memory and knowledge base.

**Subcommands:**
- `add` - Add entries to memory
- `search` - Search memory entries
- `list` - List all entries
- `export` - Export memory database

**Examples:**
```bash
# Add analysis result to memory
brains memory add --file analysis-result.json --tags "llm,suspicious"

# Search memory entries
brains memory search --query "suspicious variables" --limit 10

# List recent entries
brains memory list --recent 20

# Export memory database
brains memory export --output memory-backup.json
```

#### `brains report`

Generate formatted reports from analysis results.

**Basic Syntax:**
```bash
brains report generate [OPTIONS] --input <REPORT>
```

**Options:**
- `--input <REPORT>` - Input analysis report
- `--format <FORMAT>` - Output format (json, yaml, pdf, html)
- `--output <FILE>` - Output file path
- `--template <TEMPLATE>` - Report template (research, forensic, summary)
- `--include-metadata` - Include detailed metadata

**Examples:**
```bash
# Generate PDF research report
brains report generate \
  --input analysis-results.json \
  --format pdf \
  --template research \
  --output research-findings.pdf

# Generate HTML summary
brains report generate \
  --input analysis-results.json \
  --format html \
  --template summary \
  --output summary.html
```

#### `brains server`

Run analysis server for API access.

**Subcommands:**
- `start` - Start server
- `stop` - Stop server
- `status` - Check server status

**Server Options:**
- `--port <PORT>` - Server port (default: 8080)
- `--host <HOST>` - Server host (default: 127.0.0.1)
- `--config <FILE>` - Configuration file path
- `--workers <N>` - Number of worker threads
- `--max-request-size <SIZE>` - Maximum request size

**Examples:**
```bash
# Start server with default settings
brains server start

# Start server with custom configuration
brains server start \
  --port 9090 \
  --host 0.0.0.0 \
  --workers 4 \
  --config ./server-config.toml

# Check server status
brains server status
```

## Analysis Workflow

### 1. Single File Analysis

```bash
# Step 1: Analyze the file
brains forensics analyze --input suspicious.rs --output results.json

# Step 2: Review results
cat results.json | jq '.patterns[] | select(.confidence > 0.7)'

# Step 3: Generate report
brains report generate --input results.json --format pdf --output report.pdf
```

### 2. Project Analysis

```bash
# Step 1: Analyze entire project
brains forensics analyze \
  --input ./project-root \
  --recursive \
  --languages rust,javascript \
  --output project-analysis.json

# Step 2: Correlate findings
brains forensics correlate \
  --input project-analysis.json \
  --intent-reconstruction \
  --output correlation-results.json

# Step 3: Generate comprehensive report
brains report generate \
  --input correlation-results.json \
  --format html \
  --template research \
  --output project-report.html
```

### 3. Batch Research Analysis

```bash
# Step 1: Analyze dataset
brains forensics analyze \
  --input ./research-dataset \
  --recursive \
  --parallel 8 \
  --output batch-results/

# Step 2: Aggregate results
brains report aggregate \
  --input batch-results/ \
  --output aggregated-results.json

# Step 3: Generate research findings
brains report generate \
  --input aggregated-results.json \
  --format pdf \
  --template research \
  --output research-paper-data.pdf
```

## API Usage

### Starting the Server

```bash
brains server start --port 8080
```

### REST API Endpoints

#### Health Check
```bash
curl http://localhost:8080/api/v1/health
```

#### Submit Analysis
```bash
curl -X POST http://localhost:8080/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "fn main() { let data = 42; println!(\"{}\", data); }",
    "language": "rust",
    "options": {
      "signed": true,
      "verbose": false
    }
  }'
```

#### Get Analysis Results
```bash
curl http://localhost:8080/api/v1/analysis/{analysis_id}
```

#### List Analysis History
```bash
curl http://localhost:8080/api/v1/analyses?limit=10
```

### WebSocket API

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

// Submit analysis
ws.send(JSON.stringify({
  type: 'analyze',
  payload: {
    code: 'fn main() { println!("Hello, world!"); }',
    language: 'rust'
  }
}));

// Receive results
ws.onmessage = (event) => {
  const result = JSON.parse(event.data);
  console.log('Analysis result:', result);
};
```

## Configuration

### Configuration File

Create `~/.config/brains/config.toml`:

```toml
[analysis]
max_file_size = "10MB"
timeout = "300s"
default_languages = ["rust", "javascript", "python"]
parallel_workers = 4

[patterns]
confidence_threshold = 0.5
enable_llm_detection = true
enable_surveillance_detection = true

[server]
port = 8080
host = "127.0.0.1"
max_connections = 100
request_timeout = "30s"

[logging]
level = "info"
format = "json"
file = "~/.cache/brains/logs/brains.log"

[security]
enable_signing = true
key_path = "~/.config/brains/signing.key"
verify_signatures = true

[memory]
database_path = "~/.cache/brains/memory.db"
max_entries = 10000
cleanup_interval = "1h"
```

### Environment Variables

```bash
# Analysis settings
export BRAINS_MAX_FILE_SIZE=10MB
export BRAINS_ANALYSIS_TIMEOUT=300s
export BRAINS_PARALLEL_WORKERS=4

# Server settings
export BRAINS_SERVER_PORT=8080
export BRAINS_SERVER_HOST=0.0.0.0

# Logging
export BRAINS_LOG_LEVEL=info
export BRAINS_LOG_FORMAT=json

# Security
export BRAINS_SIGNING_KEY_PATH=~/.config/brains/signing.key
export BRAINS_ENABLE_SIGNING=true
```

## Output Formats

### JSON Report Structure

```json
{
  "analysis_id": "uuid-string",
  "timestamp": "2024-01-01T12:00:00Z",
  "input_files": ["file1.rs", "file2.js"],
  "analysis_config": {
    "languages": ["rust", "javascript"],
    "signed": true,
    "timeout": 300
  },
  "results": [
    {
      "file_path": "file1.rs",
      "language": "rust",
      "patterns": [
        {
          "pattern_name": "SuspiciousVariableName",
          "confidence": 0.8,
          "evidence": "let data = 42;",
          "location": {
            "line_start": 2,
            "line_end": 2,
            "column_start": 8,
            "column_end": 12
          },
          "metadata": {
            "variable_name": "data",
            "pattern_type": "generic_identifier"
          }
        }
      ],
      "provenance": {
        "model_family": "GPT4Turbo",
        "confidence": 0.75,
        "generation_timeframe": {
          "start": "2023-01-01T00:00:00Z",
          "end": "2024-01-01T00:00:00Z"
        }
      }
    }
  ],
  "correlation": {
    "intent_graph": {
      "nodes": [],
      "edges": []
    },
    "orchestration_patterns": []
  },
  "signature": "cryptographic-signature-if-enabled"
}
```

### YAML Report Structure

```yaml
analysis_id: uuid-string
timestamp: 2024-01-01T12:00:00Z
input_files:
  - file1.rs
  - file2.js
analysis_config:
  languages: [rust, javascript]
  signed: true
  timeout: 300
results:
  - file_path: file1.rs
    language: rust
    patterns:
      - pattern_name: SuspiciousVariableName
        confidence: 0.8
        evidence: "let data = 42;"
        location:
          line_start: 2
          line_end: 2
          column_start: 8
          column_end: 12
```

## Advanced Features

### Pattern Detection Customization

```bash
# Create custom pattern file
cat > custom-patterns.toml << 'EOF'
[patterns.suspicious_crypto]
name = "Suspicious Cryptographic Operations"
description = "Detect potentially malicious crypto usage"
confidence = 0.9
rules = [
  "matches crypto::.*::encrypt",
  "matches openssl::.*::cipher"
]

[patterns.data_exfiltration]
name = "Data Exfiltration Patterns"
description = "Detect data collection and transmission"
confidence = 0.8
rules = [
  "matches std::net::.*::send",
  "matches reqwest::.*::post"
]
EOF

# Use custom patterns
brains forensics analyze \
  --input ./target \
  --patterns custom-patterns.toml \
  --output results.json
```

### Signature Verification

```bash
# Generate signing key
brains keys generate --output signing.key

# Analyze with signing
brains forensics analyze \
  --input ./code \
  --signed \
  --key signing.key \
  --output signed-report.json

# Verify signature
brains verify \
  --input signed-report.json \
  --key signing.key
```

### Memory Management

```bash
# Add analysis to memory with tags
brains memory add \
  --file analysis-result.json \
  --tags "research,llm-detection,high-confidence" \
  --description "GPT-4 generated code analysis"

# Search memory by tags
brains memory search \
  --tags "llm-detection" \
  --confidence-min 0.8 \
  --limit 20

# Export memory for backup
brains memory export \
  --output memory-backup-$(date +%Y%m%d).json \
  --format json
```

## Troubleshooting

### Common Issues

1. **Analysis Timeout**
   ```bash
   # Increase timeout
   brains forensics analyze --input ./large-file --timeout 600
   ```

2. **Memory Issues**
   ```bash
   # Process files in smaller batches
   brains forensics analyze --input ./large-dir --batch-size 50
   ```

3. **Language Detection Problems**
   ```bash
   # Explicitly specify language
   brains forensics analyze --input ./file --languages rust
   ```

### Debug Mode

```bash
# Enable debug output
export BRAINS_LOG_LEVEL=debug
export RUST_BACKTRACE=1

# Run with verbose logging
brains forensics analyze --input ./test --verbose
```

### Performance Optimization

```bash
# Optimize for large datasets
brains forensics analyze \
  --input ./large-dataset \
  --parallel 8 \
  --batch-size 100 \
  --cache-results \
  --output results/
```

## Best Practices

### Research Workflow

1. **Reproducibility**
   - Always use signed reports for research
   - Document analysis configuration
   - Maintain input file hashes

2. **Validation**
   - Cross-validate results with multiple runs
   - Use confidence thresholds appropriately
   - Verify signatures before publication

3. **Data Management**
   - Organize results by analysis date
   - Use descriptive filenames
   - Back up memory database regularly

### Performance

1. **Batch Processing**
   - Process files in parallel
   - Use appropriate batch sizes
   - Monitor memory usage

2. **Caching**
   - Enable result caching for repeated analysis
   - Use memory database for pattern storage
   - Clear cache periodically

3. **Resource Management**
   - Set appropriate timeouts
   - Monitor disk space usage
   - Use streaming for large files

This user guide provides comprehensive coverage of the Brains Forensic Platform capabilities. For additional help or advanced usage scenarios, consult the architecture documentation or deployment guide.