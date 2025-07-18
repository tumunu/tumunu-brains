//! Forensic analysis traits and implementations
use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use chrono::{DateTime, Utc};

pub mod ast_pattern_analyzer;

pub use ast_pattern_analyzer::ASTPatternAnalyzer;

/// Core forensic analysis trait
pub trait ForensicAnalyzer {
    type Pattern;
    type Evidence;
    type Result;

    /// Analyze input for forensic patterns
    fn analyze(&self, input: &ForensicInput) -> Vec<ForensicResult<Self::Result>>;

    /// Get analyzer metadata
    fn metadata(&self) -> AnalyzerMetadata;
}

/// Input for forensic analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicInput {
    pub content: String,
    pub path: Option<PathBuf>,
    pub language: String,
    pub metadata: serde_json::Value,
}

/// Analysis result with confidence
#[derive(Debug, Serialize, Deserialize)]
pub struct ForensicResult<T> {
    pub pattern: String,
    pub confidence: f64,
    pub evidence: Vec<Evidence>,
    pub details: T,
    pub provenance: Provenance,
}

/// Evidence supporting a forensic finding
#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub location: CodeLocation,
    pub signature: String,
    pub confidence: f64,
}

/// Types of forensic evidence
#[derive(Debug, Serialize, Deserialize)]
pub enum EvidenceType {
    SyntacticPattern { pattern_name: String },
    SemanticPattern { pattern_name: String },
    StylisticFeature { feature: String },
    StatisticalAnomaly { metric: String, value: f64 },
}

/// Code location metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file_path: Option<String>,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub context: Option<String>,
}

/// Provenance information
#[derive(Debug, Serialize, Deserialize)]
pub struct Provenance {
    pub analyzer_version: String,
    pub timestamp: DateTime<Utc>,
    pub input_hash: String,
}

/// Analyzer metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalyzerMetadata {
    pub name: String,
    pub version: String,
    pub pattern_types: Vec<String>,
    pub confidence_model: String,
}

/// Pattern detection trait
pub trait PatternDetector {
    fn detect_patterns(&self, input: &str) -> Vec<PatternMatch>;
}

/// Pattern match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub confidence: f64,
    pub evidence: String,
    pub line_range: (usize, usize),
    pub node_range: (usize, usize),
    pub context: String,
    pub metadata: serde_json::Value,
}

/// Confidence scoring trait
pub trait ConfidenceScorer {
    fn calculate_confidence(&self, matches: &[PatternMatch]) -> f64;
}

/// Evidence collector trait
pub trait EvidenceCollector {
    fn collect_evidence(&self, matches: &[PatternMatch]) -> Vec<Evidence>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAnalyzer;
    
    impl ForensicAnalyzer for TestAnalyzer {
        type Pattern = String;
        type Evidence = Evidence;
        type Result = serde_json::Value;

        fn analyze(&self, _input: &ForensicInput) -> Vec<ForensicResult<Self::Result>> {
            vec![]
        }

        fn metadata(&self) -> AnalyzerMetadata {
            AnalyzerMetadata {
                name: "Test".to_string(),
                version: "0.1".to_string(),
                pattern_types: vec!["test".to_string()],
                confidence_model: "basic".to_string(),
            }
        }
    }

    #[test]
    fn test_analyzer_trait() {
        let analyzer = TestAnalyzer;
        let metadata = analyzer.metadata();
        assert_eq!(metadata.name, "Test");
    }
}