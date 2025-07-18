# Developer Guide

Guide for contributing to and extending the Brains Forensic Platform.

## Development Environment Setup

### Prerequisites

- **Rust**: 1.70+ with latest toolchain
- **Git**: For version control
- **IDE**: VS Code with rust-analyzer (recommended)
- **System Libraries**: Build tools and tree-sitter dependencies

### Initial Setup

```bash
# Clone repository
git clone https://github.com/your-org/brains-forensic-platform.git
cd brains-forensic-platform

# Install development dependencies
rustup component add rustfmt clippy
cargo install cargo-watch cargo-nextest

# Build development version
cargo build

# Run tests
cargo test
```

### Development Tools

```bash
# Code formatting
cargo fmt

# Linting
cargo clippy

# Watch mode for development
cargo watch -x check -x test

# Documentation generation
cargo doc --open
```

## Project Structure

```
brains-forensic-platform/
├── brains-cli/           # Command-line interface
├── brains-core/          # Core orchestration logic
├── brains-correlation/   # Fragment correlation engine
├── brains-detection/     # Detection interfaces and types
├── brains-forensics/     # AST pattern analysis
├── brains-memory/        # Memory management
├── brains-ontology/      # Pattern ontology and knowledge base
├── brains-provenance/    # Provenance fingerprinting
├── brains-reports/       # Report generation
├── docs/                 # Documentation
├── examples/             # Example usage
├── tests/                # Integration tests
└── Cargo.toml           # Workspace configuration
```

## Architecture Overview

### Module Dependencies

```
┌─────────────────┐
│   brains-cli    │
└─────────────────┘
         │
         ▼
┌─────────────────┐    ┌─────────────────┐
│  brains-core    │───▶│brains-forensics │
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│brains-detection │    │brains-provenance│
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│brains-ontology  │    │brains-correlation│
└─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│brains-memory    │    │brains-reports   │
└─────────────────┘    └─────────────────┘
```

### Key Traits and Interfaces

#### ForensicAnalyzer Trait

```rust
pub trait ForensicAnalyzer {
    type Pattern;
    type Evidence;
    type Result;

    fn analyze(&self, input: &ForensicInput) -> Vec<ForensicResult<Self::Result>>;
    fn metadata(&self) -> AnalyzerMetadata;
}
```

#### PatternEngine Trait

```rust
pub trait PatternEngine {
    fn detect_patterns(&self, input: &str) -> Vec<PatternMatch>;
    fn update_patterns(&mut self, patterns: &[DetectionOntology]) -> anyhow::Result<()>;
    fn performance_metrics(&self) -> PerformanceMetrics;
}
```

#### ASTPatternAnalyzer Trait

```rust
pub trait ASTPatternAnalyzerTrait {
    fn language(&self) -> &'static str;
    fn analyze_code(&mut self, source_code: &str) -> Vec<PatternMatch>;
}
```

## Adding New Features

### 1. Adding a New Language Analyzer

Create a new analyzer for a specific programming language:

```rust
// In brains-forensics/src/ast_pattern_analyzer.rs

pub struct GoPatternAnalyzer {
    parser: Parser,
}

impl GoPatternAnalyzer {
    pub fn new() -> anyhow::Result<Self> {
        let mut parser = Parser::new();
        unsafe {
            parser.set_language(tree_sitter_go())
                .map_err(|e| anyhow::anyhow!("Error loading Go grammar: {}", e))?;
        }
        Ok(Self { parser })
    }

    fn detect_go_patterns(&self, cursor: &mut TreeCursor, source: &str, results: &mut Vec<PatternMatch>) {
        // Implement Go-specific pattern detection
        loop {
            let node = cursor.node();
            
            // Example: Detect suspicious goroutine patterns
            if node.kind() == "go_statement" {
                let code = node.utf8_text(source.as_bytes()).unwrap_or_default();
                
                results.push(PatternMatch {
                    pattern_name: "SuspiciousGoroutine".to_string(),
                    confidence: 0.6,
                    evidence: code.to_string(),
                    line_range: (node.start_position().row, node.end_position().row),
                    node_range: (node.start_byte(), node.end_byte()),
                    context: "Goroutine pattern analysis".to_string(),
                    metadata: serde_json::json!({
                        "pattern_type": "concurrency"
                    }),
                });
            }

            if cursor.goto_first_child() {
                self.detect_go_patterns(cursor, source, results);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

impl ASTPatternAnalyzerTrait for GoPatternAnalyzer {
    fn language(&self) -> &'static str {
        "go"
    }

    fn analyze_code(&mut self, source_code: &str) -> Vec<PatternMatch> {
        let tree = match self.parser.parse(source_code, None) {
            Some(tree) => tree,
            None => return vec![],
        };

        let mut cursor = tree.root_node().walk();
        let mut results = Vec::new();

        self.detect_go_patterns(&mut cursor, source_code, &mut results);

        results
    }
}
```

**Integration Steps:**

1. Add tree-sitter-go to workspace dependencies
2. Update ASTPatternAnalyzer to include GoPatternAnalyzer
3. Add Go language support to CLI
4. Write tests for Go pattern detection
5. Update documentation

### 2. Adding Custom Pattern Types

Define new pattern types in the ontology:

```rust
// In brains-ontology/src/lib.rs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CustomPatternType {
    CryptographicOperation { algorithm: String, key_size: Option<u32> },
    NetworkCommunication { protocol: String, endpoint: String },
    DataExfiltration { method: String, volume: Option<u64> },
    Obfuscation { technique: String, complexity: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomPatternEntry {
    pub id: String,
    pub pattern_type: CustomPatternType,
    pub detection_rules: Vec<String>,
    pub confidence_threshold: f64,
    pub metadata: HashMap<String, String>,
}
```

**Integration Steps:**

1. Extend PatternEntry with custom fields
2. Implement detection logic in analyzers
3. Add pattern validation
4. Update report generation
5. Add tests for new patterns

### 3. Adding New Report Formats

Create custom report generators:

```rust
// In brains-reports/src/generators/

pub struct MarkdownReportGenerator;

impl ReportGenerator for MarkdownReportGenerator {
    fn generate(&self, analysis: &AnalysisResult) -> anyhow::Result<String> {
        let mut output = String::new();
        
        // Header
        output.push_str("# Forensic Analysis Report\n\n");
        output.push_str(&format!("**Analysis ID:** {}\n", analysis.id));
        output.push_str(&format!("**Timestamp:** {}\n\n", analysis.timestamp));
        
        // Summary
        output.push_str("## Summary\n\n");
        output.push_str(&format!("- **Files Analyzed:** {}\n", analysis.files.len()));
        output.push_str(&format!("- **Patterns Detected:** {}\n", analysis.total_patterns()));
        output.push_str(&format!("- **High Confidence:** {}\n\n", analysis.high_confidence_patterns()));
        
        // Detailed findings
        output.push_str("## Detailed Findings\n\n");
        for result in &analysis.results {
            output.push_str(&format!("### {}\n\n", result.file_path));
            
            for pattern in &result.patterns {
                output.push_str(&format!("- **{}** (confidence: {:.2})\n", 
                    pattern.pattern_name, pattern.confidence));
                output.push_str(&format!("  - Evidence: `{}`\n", pattern.evidence));
                output.push_str(&format!("  - Location: lines {}-{}\n\n", 
                    pattern.line_range.0, pattern.line_range.1));
            }
        }
        
        Ok(output)
    }
    
    fn format_name(&self) -> &'static str {
        "markdown"
    }
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_pattern_detection() {
        let mut analyzer = RustPatternAnalyzer::new().unwrap();
        
        let code = r#"
        fn main() {
            let data = 42;
            let result = process_data(data);
            println!("{}", result);
        }
        "#;
        
        let patterns = analyzer.analyze_code(code);
        
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.pattern_name == "SuspiciousVariableName"));
    }

    #[test]
    fn test_confidence_scoring() {
        let mut analyzer = RustPatternAnalyzer::new().unwrap();
        let code = "let data = 42;";
        let patterns = analyzer.analyze_code(code);
        
        assert!(patterns[0].confidence >= 0.0 && patterns[0].confidence <= 1.0);
    }
}
```

### Integration Tests

```rust
// In tests/integration_tests.rs

use brains_cli::*;
use std::process::Command;

#[test]
fn test_cli_analysis() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "brains", "forensics", "analyze", "--input", "test_data/sample.rs"])
        .output()
        .expect("Failed to execute command");
    
    assert!(output.status.success());
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analysis complete"));
}

#[test]
fn test_server_mode() {
    // Test server startup and API endpoints
    let mut server = Command::new("cargo")
        .args(&["run", "--bin", "brains", "server", "start", "--port", "8081"])
        .spawn()
        .expect("Failed to start server");
    
    // Wait for server to start
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Test health endpoint
    let response = reqwest::blocking::get("http://localhost:8081/api/v1/health")
        .expect("Failed to make request");
    
    assert!(response.status().is_success());
    
    // Clean up
    server.kill().expect("Failed to kill server");
}
```

### Property-Based Tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_pattern_detection_properties(
        code in "fn main\\(\\) \\{[^}]*\\}",
        language in "rust|javascript|python"
    ) {
        let mut analyzer = ASTPatternAnalyzer::new().unwrap();
        let patterns = analyzer.analyze_code(&code, &language);
        
        // Property: All patterns should have valid confidence scores
        for pattern in &patterns {
            prop_assert!(pattern.confidence >= 0.0 && pattern.confidence <= 1.0);
        }
        
        // Property: Pattern locations should be within source bounds
        for pattern in &patterns {
            prop_assert!(pattern.node_range.0 <= pattern.node_range.1);
            prop_assert!(pattern.node_range.1 <= code.len());
        }
    }
}
```

## Code Style and Standards

### Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Linting

```bash
# Run clippy
cargo clippy

# Run clippy with all features
cargo clippy --all-features --all-targets
```

### Documentation

```rust
/// Analyzes source code for suspicious patterns using AST parsing.
/// 
/// This function parses the provided source code into an Abstract Syntax Tree
/// and traverses it to detect patterns indicative of LLM-generated code,
/// surveillance tools, or other forensic indicators.
/// 
/// # Arguments
/// 
/// * `source_code` - The source code to analyze
/// * `language` - The programming language of the source code
/// 
/// # Returns
/// 
/// A vector of `PatternMatch` results, each containing:
/// - Pattern name and confidence score
/// - Evidence string and location information
/// - Metadata for further analysis
/// 
/// # Examples
/// 
/// ```rust
/// use brains_forensics::ASTPatternAnalyzer;
/// 
/// let mut analyzer = ASTPatternAnalyzer::new()?;
/// let patterns = analyzer.analyze_code("fn main() { let data = 42; }", "rust");
/// 
/// for pattern in patterns {
///     println!("Found pattern: {} (confidence: {})", 
///              pattern.pattern_name, pattern.confidence);
/// }
/// ```
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The source code cannot be parsed
/// - The language is not supported
/// - Internal analysis fails
pub fn analyze_code(&mut self, source_code: &str, language: &str) -> Vec<PatternMatch> {
    // Implementation...
}
```

## Performance Considerations

### Memory Management

```rust
// Use streaming for large files
use std::io::BufReader;

fn process_large_file(path: &Path) -> anyhow::Result<Vec<PatternMatch>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut results = Vec::new();
    
    // Process file in chunks to avoid memory issues
    for chunk in reader.lines().chunks(1000) {
        let chunk_content: String = chunk.collect::<Result<Vec<_>, _>>()?.join("\n");
        let chunk_results = analyze_chunk(&chunk_content)?;
        results.extend(chunk_results);
    }
    
    Ok(results)
}
```

### Parallelization

```rust
use rayon::prelude::*;

fn analyze_files_parallel(files: &[PathBuf]) -> anyhow::Result<Vec<AnalysisResult>> {
    files
        .par_iter()
        .map(|path| {
            let mut analyzer = ASTPatternAnalyzer::new()?;
            let content = std::fs::read_to_string(path)?;
            let language = detect_language(path)?;
            let patterns = analyzer.analyze_code(&content, &language);
            
            Ok(AnalysisResult {
                file_path: path.clone(),
                patterns,
                metadata: Default::default(),
            })
        })
        .collect()
}
```

### Caching

```rust
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Default)]
pub struct AnalysisCache {
    cache: RwLock<HashMap<String, Vec<PatternMatch>>>,
}

impl AnalysisCache {
    pub fn get(&self, key: &str) -> Option<Vec<PatternMatch>> {
        self.cache.read().unwrap().get(key).cloned()
    }
    
    pub fn insert(&self, key: String, value: Vec<PatternMatch>) {
        self.cache.write().unwrap().insert(key, value);
    }
}
```

## Error Handling

### Custom Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalysisError {
    #[error("Failed to parse source code: {0}")]
    ParseError(String),
    
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
    
    #[error("Analysis timeout after {seconds} seconds")]
    Timeout { seconds: u64 },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Pattern detection failed: {0}")]
    PatternDetection(String),
}
```

### Error Propagation

```rust
fn analyze_with_error_handling(input: &str) -> Result<Vec<PatternMatch>, AnalysisError> {
    let language = detect_language_from_content(input)
        .ok_or_else(|| AnalysisError::UnsupportedLanguage("unknown".to_string()))?;
    
    let mut analyzer = ASTPatternAnalyzer::new()
        .map_err(|e| AnalysisError::PatternDetection(e.to_string()))?;
    
    let patterns = analyzer.analyze_code(input, &language);
    
    if patterns.is_empty() {
        return Err(AnalysisError::PatternDetection(
            "No patterns detected in valid code".to_string()
        ));
    }
    
    Ok(patterns)
}
```

## Debugging

### Debug Logging

```rust
use tracing::{debug, info, warn, error};

fn analyze_with_logging(input: &str) -> anyhow::Result<Vec<PatternMatch>> {
    info!("Starting analysis of {} bytes", input.len());
    
    let language = detect_language_from_content(input);
    debug!("Detected language: {:?}", language);
    
    let mut analyzer = ASTPatternAnalyzer::new()?;
    let patterns = analyzer.analyze_code(input, &language.unwrap_or("unknown".to_string()));
    
    info!("Analysis complete. Found {} patterns", patterns.len());
    
    for pattern in &patterns {
        debug!("Pattern: {} (confidence: {})", pattern.pattern_name, pattern.confidence);
    }
    
    Ok(patterns)
}
```

### Debug Output

```rust
#[cfg(debug_assertions)]
fn debug_ast_structure(node: &Node, source: &str, depth: usize) {
    let indent = "  ".repeat(depth);
    let node_text = node.utf8_text(source.as_bytes()).unwrap_or("<invalid>");
    
    println!("{}Node: {} | Text: {:?}", indent, node.kind(), 
             node_text.chars().take(50).collect::<String>());
    
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            debug_ast_structure(&child, source, depth + 1);
        }
    }
}
```

## Contributing Guidelines

### Pull Request Process

1. **Fork and Branch**
   ```bash
   git checkout -b feature/new-analyzer
   ```

2. **Develop and Test**
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```

3. **Document Changes**
   - Update relevant documentation
   - Add/update tests
   - Update CHANGELOG.md

4. **Submit PR**
   - Clear description of changes
   - Link to related issues
   - Include test results

### Code Review Checklist

- [ ] Code follows Rust best practices
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Performance impact is considered
- [ ] Error handling is appropriate
- [ ] Security implications are reviewed
- [ ] API changes are backward compatible

### Release Process

1. Update version numbers in Cargo.toml files
2. Update CHANGELOG.md
3. Create release branch
4. Run full test suite
5. Create GitHub release
6. Publish to crates.io (if applicable)

This developer guide provides comprehensive information for contributing to the Brains Forensic Platform. For specific technical questions or advanced development scenarios, consult the architecture documentation or reach out to the development team.