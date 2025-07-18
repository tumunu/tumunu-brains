# Architecture Overview

This document provides a comprehensive overview of the Brains Forensic Platform architecture, designed for research-grade forensic analysis of potentially malicious code patterns.

## System Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────────────┐
│ Brains Forensic Platform                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Input Layer   │  │  Analysis Core  │  │  Output Layer   │  │
│  │                 │  │                 │  │                 │  │
│  │ • CLI Interface │  │ • AST Analysis  │  │ • JSON Reports  │  │
│  │ • REST API      │  │ • Provenance    │  │ • Signed Docs   │  │
│  │ • File I/O      │  │ • Correlation   │  │ • Audit Logs    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Core Modules

#### 1. brains-cli
**Purpose**: Command-line interface and main binary
**Key Components**:
- Argument parsing and command routing
- Analysis orchestration
- Report generation and output formatting
- Server mode for API endpoints

#### 2. brains-forensics
**Purpose**: AST-based pattern detection and analysis
**Key Components**:
- `ASTPatternAnalyzer`: Multi-language AST parsing
- `RustPatternAnalyzer`: Rust-specific pattern detection
- `JavascriptPatternAnalyzer`: JavaScript pattern detection
- `PythonPatternAnalyzer`: Python pattern detection
- Tree-sitter integration for AST parsing

#### 3. brains-provenance
**Purpose**: LLM source attribution and fingerprinting
**Key Components**:
- `ProvenanceFingerprinter`: Main fingerprinting engine
- Token entropy analysis
- Model family classification
- Temporal marker detection

#### 4. brains-ontology
**Purpose**: Pattern definitions and knowledge representation
**Key Components**:
- `DetectionOntology`: Pattern knowledge base
- `PatternEntry`: Individual pattern definitions
- `EvolutionTracker`: Pattern mutation tracking
- Performance metrics and confidence models

#### 5. brains-correlation
**Purpose**: Fragment correlation and intent reconstruction
**Key Components**:
- `FragmentCorrelationEngine`: Multi-fragment analysis
- Intent graph reconstruction
- Orchestration pattern detection
- Relationship analysis between code fragments

#### 6. brains-detection
**Purpose**: Core detection interfaces and result structures
**Key Components**:
- `PatternEngine`: Detection engine trait
- `DetectionResult`: Analysis result structures
- `Evidence`: Forensic evidence representation
- Session management and result aggregation

## Data Flow Architecture

### Analysis Pipeline

```
Input Files/Code
       │
       ▼
┌─────────────────┐
│ Language        │
│ Detection       │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ AST Parsing     │
│ (tree-sitter)   │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Pattern         │
│ Detection       │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Provenance      │
│ Fingerprinting  │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Fragment        │
│ Correlation     │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Report          │
│ Generation      │
└─────────────────┘
       │
       ▼
Signed Forensic Reports
```

### Component Interaction

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   brains-cli    │───▶│ brains-forensics│───▶│brains-provenance│
│                 │    │                 │    │                 │
│ • CLI commands  │    │ • AST parsing   │    │ • Fingerprinting│
│ • Orchestration │    │ • Pattern match │    │ • Attribution   │
│ • Report output │    │ • Multi-language│    │ • Confidence    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│brains-correlation│   │brains-detection │    │brains-ontology  │
│                 │    │                 │    │                 │
│ • Intent graphs │    │ • Result types  │    │ • Pattern DB    │
│ • Orchestration │    │ • Evidence      │    │ • Ontology      │
│ • Relationships │    │ • Session mgmt  │    │ • Evolution     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Pattern Detection Architecture

### AST Pattern Analysis

The `ASTPatternAnalyzer` uses tree-sitter to parse source code and detect suspicious patterns:

```rust
// Example pattern detection flow
let analyzer = ASTPatternAnalyzer::new()?;
let patterns = analyzer.analyze_code(source, "rust");

// Detected patterns include:
// - Suspicious variable names (data, result, output)
// - Verbose function signatures
// - Excessive comments
// - Unusual control flow patterns
```

### Pattern Categories

1. **Syntactic Patterns**
   - Generic variable names
   - Verbose parameter naming
   - Comment density anomalies
   - Function signature patterns

2. **Semantic Patterns**
   - Control flow anomalies
   - Error handling patterns
   - Library usage patterns
   - API call sequences

3. **Stylistic Patterns**
   - Formatting consistency
   - Naming conventions
   - Comment styles
   - Code organization

### Confidence Scoring

Each pattern match includes:
- **Confidence Score** (0.0-1.0)
- **Evidence String** (specific code excerpt)
- **Location Data** (line/column ranges)
- **Metadata** (pattern-specific attributes)

## Provenance Fingerprinting

### Fingerprinting Process

```
Source Code Input
       │
       ▼
┌─────────────────┐
│ Token Entropy   │
│ Analysis        │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ AST Depth       │
│ Analysis        │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Model Family    │
│ Classification  │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│ Temporal Marker │
│ Detection       │
└─────────────────┘
       │
       ▼
ProvenanceFingerprint
```

### Model Attribution

The system can identify potential source models:

- **GPT-4 Turbo**: High entropy, verbose comments
- **Claude**: Detailed documentation, defensive patterns
- **Llama 2**: Specific parameter patterns
- **Unknown**: Confidence-based similarity matching

## Fragment Correlation

### Correlation Engine

The `FragmentCorrelationEngine` analyzes relationships between code fragments:

```
Fragment A    Fragment B    Fragment C
    │             │             │
    └─────────────┼─────────────┘
                  │
                  ▼
    ┌─────────────────────────────┐
    │    Correlation Analysis     │
    │                             │
    │ • Semantic similarity       │
    │ • Temporal correlation      │
    │ • Intent reconstruction     │
    │ • Orchestration patterns    │
    └─────────────────────────────┘
                  │
                  ▼
            Intent Graph
```

### Orchestration Detection

The system can identify:
- **Multi-stage attacks**: Coordinated fragments
- **Surveillance patterns**: Data collection sequences
- **Evasion techniques**: Obfuscation patterns
- **Command structures**: C&C communication patterns

## Security Architecture

### Cryptographic Signing

All forensic reports are cryptographically signed:

```rust
// Report signing process
let report = generate_forensic_report(analysis_results);
let signature = signing_key.sign(report.hash());
let signed_report = SignedReport { report, signature };
```

### Audit Trail

Complete provenance chain:
- Input file hashes
- Analysis configuration
- Pattern detection results
- Correlation findings
- Report generation metadata

### Sandboxing

Analysis runs in isolated environments:
- No code execution
- Read-only file access
- Memory usage limits
- Timeout protection

## Performance Architecture

### Parallel Processing

```
Input Files
     │
     ▼
┌─────────────────┐
│ File Queue      │
│ Distribution    │
└─────────────────┘
     │
     ├─────────────────┐
     │                 │
     ▼                 ▼
┌─────────────┐  ┌─────────────┐
│ Worker 1    │  │ Worker N    │
│ • Parse AST │  │ • Parse AST │
│ • Detect    │  │ • Detect    │
│ • Analyze   │  │ • Analyze   │
└─────────────┘  └─────────────┘
     │                 │
     └─────────────────┘
               │
               ▼
    ┌─────────────────┐
    │ Result          │
    │ Aggregation     │
    └─────────────────┘
```

### Memory Management

- Streaming file processing
- Incremental AST parsing
- Result batching
- Memory pool allocation

### Caching Strategy

- Pattern database caching
- AST parse result caching
- Model signature caching
- Correlation result caching

## Extension Architecture

### Plugin System

```rust
// Plugin interface
trait ForensicPlugin {
    fn analyze(&self, input: &ForensicInput) -> Vec<ForensicResult>;
    fn metadata(&self) -> PluginMetadata;
}

// Plugin registration
registry.register_plugin(Box::new(CustomPatternPlugin));
```

### Language Support

Adding new language support:

1. Add tree-sitter grammar dependency
2. Implement language-specific analyzer
3. Define pattern detection rules
4. Register with analysis engine

### Pattern Extension

Adding new pattern types:

1. Define pattern in ontology
2. Implement detection logic
3. Add confidence scoring
4. Include in correlation engine

## Deployment Architecture

### Standalone Mode

```
┌─────────────────┐
│ brains CLI      │
│                 │
│ • File input    │
│ • Local analysis│
│ • Report output │
└─────────────────┘
```

### Server Mode

```
┌─────────────────┐    ┌─────────────────┐
│ Web UI/Client   │───▶│ brains Server   │
│                 │    │                 │
│ • File upload   │    │ • REST API      │
│ • Results view  │    │ • WebSocket     │
│ • Report DL     │    │ • Analysis queue│
└─────────────────┘    └─────────────────┘
```

### Distributed Mode

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Analysis Client │───▶│ Coordinator     │───▶│ Worker Nodes    │
│                 │    │                 │    │                 │
│ • Job submit    │    │ • Task queue    │    │ • Analysis      │
│ • Result fetch  │    │ • Load balance  │    │ • Result return │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Research Integration

### Workflow Integration

The platform supports research workflows through:

1. **Batch Processing**: Large dataset analysis
2. **Reproducibility**: Deterministic analysis results
3. **Provenance**: Complete audit trail
4. **Validation**: Cross-validation capabilities
5. **Publication**: Cryptographically verifiable results

### Data Formats

- **Input**: Source code files, ZIP archives, JSON datasets
- **Output**: JSON reports, CSV data, PDF summaries
- **Intermediate**: AST representations, pattern databases
- **Audit**: Structured logs, provenance chains

This architecture ensures the platform maintains research-grade standards while providing practical forensic analysis capabilities for detecting and analyzing suspicious code patterns.