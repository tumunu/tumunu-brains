//! # Brains Detection
//!
//! Detection trait system for forensic pattern analysis.
//! Implements the SOLID principle-based detection interfaces
//! identified in the architectural critique.

use brains_ontology::{DetectionOntology, PerformanceMetrics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Result of pattern detection with full provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub pattern_id: Uuid,
    pub confidence: f64,
    pub evidence: Vec<Evidence>,
    pub provenance: Provenance,
    pub rationale: String,
    pub ontology_tags: Vec<String>,
    pub detection_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Evidence supporting a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,
    pub location: CodeLocation,
    pub signature: String,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

/// Types of evidence for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    SyntacticPattern { pattern_name: String },
    SemanticFeature { feature_name: String },
    StatisticalAnomaly { metric: String, threshold: f64 },
    ProvenanceMarker { source: String },
    StructuralSignature { signature_type: String },
}

/// Code location for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file_path: Option<String>,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub context: Option<String>,
}

/// Provenance information for detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub git_hash: Option<String>,
    pub build_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub analyzer_version: String,
    pub environment_fingerprint: String,
    pub input_hash: String,
}

/// Classification of code origin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CodeOrigin {
    HumanWritten {
        confidence: f64,
        indicators: Vec<String>,
        style_markers: Vec<String>,
    },
    LLMGenerated {
        confidence: f64,
        model_family: Option<String>,
        signatures: Vec<String>,
        generation_indicators: Vec<String>,
    },
    Hybrid {
        confidence: f64,
        breakdown: HashMap<String, f64>,
        human_percentage: f64,
        llm_percentage: f64,
    },
    Unknown {
        reasons: Vec<String>,
        ambiguity_score: f64,
    },
}

/// Analysis session for investigation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub session_id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub investigator_id: String,
    pub case_id: String,
    pub inputs: Vec<AnalysisInput>,
    pub results: Vec<DetectionResult>,
    pub annotations: Vec<UserAnnotation>,
    pub reproducibility_hash: String,
}

/// Input to analysis session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisInput {
    pub input_id: Uuid,
    pub input_type: InputType,
    pub content_hash: String,
    pub metadata: HashMap<String, String>,
}

/// Types of analysis input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputType {
    SourceCode { language: String, file_path: String },
    Binary { format: String, architecture: String },
    NetworkCapture { protocol: String },
    LogEntry { log_type: String },
    Artifact { artifact_type: String },
}

/// User annotation for investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAnnotation {
    pub annotation_id: Uuid,
    pub investigator_id: String,
    pub target_id: Uuid, // Reference to result or input
    pub annotation_text: String,
    pub confidence_override: Option<f64>,
    pub validation_status: ValidationStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature: Option<String>, // Cryptographic signature
}

/// Validation status for annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Confirmed,
    Disputed,
    Uncertain,
    RequiresReview,
}

// =============================================================================
// Detection Trait System (SOLID Principles)
// =============================================================================

/// Core trait for LLM-generated code detection
pub trait LLMDetector {
    /// Detect LLM signatures in code
    fn detect_llm_signatures(&self, code: &str) -> anyhow::Result<DetectionResult>;

    /// Validate confidence of detection result
    fn validate_confidence(&self, result: &DetectionResult) -> bool;

    /// Get supported languages for this detector
    fn supported_languages(&self) -> Vec<String>;

    /// Update detector with new training data
    fn update_model(&mut self, training_data: &[TrainingExample]) -> anyhow::Result<()>;
}

/// Trait for surveillance pattern analysis
pub trait SurveillanceAnalyzer {
    /// Analyze patterns resembling XKEYSCORE
    fn analyze_xkeyscore_patterns(&self, code: &str) -> anyhow::Result<DetectionResult>;

    /// Analyze patterns resembling PRISM
    fn analyze_prism_patterns(&self, code: &str) -> anyhow::Result<DetectionResult>;

    /// Analyze patterns resembling MUSCULAR
    fn analyze_muscular_patterns(&self, code: &str) -> anyhow::Result<DetectionResult>;

    /// Generic surveillance pattern analysis
    fn analyze_surveillance_patterns(&self, code: &str, pattern_type: &str) -> anyhow::Result<DetectionResult>;
}

/// Trait for code origin classification
pub trait CodeClassifier {
    /// Classify the origin of code
    fn classify_origin(&self, code: &str) -> anyhow::Result<CodeOrigin>;

    /// Explain the classification reasoning
    fn explain_classification(&self, classification: &CodeOrigin) -> String;

    /// Get confidence threshold for classification
    fn confidence_threshold(&self) -> f64;
}

/// Trait for pattern engines
pub trait PatternEngine {
    /// Get unique engine identifier
    fn id(&self) -> &str;

    /// Analyze code for patterns
    fn analyze(&self, code: &str) -> anyhow::Result<Vec<DetectionResult>>;

    /// Get engine capabilities
    fn capabilities(&self) -> EngineCapabilities;

    /// Update engine with new patterns
    fn update_patterns(&mut self, patterns: &[DetectionOntology]) -> anyhow::Result<()>;

    /// Get performance metrics
    fn performance_metrics(&self) -> PerformanceMetrics;
}

/// Capabilities of a pattern engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineCapabilities {
    pub supported_languages: Vec<String>,
    pub pattern_types: Vec<String>,
    pub features: Vec<String>,
    pub performance_characteristics: HashMap<String, f64>,
}

/// Training example for model updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    pub code: String,
    pub expected_origin: CodeOrigin,
    pub metadata: HashMap<String, String>,
}

// =============================================================================
// Concrete Implementations
// =============================================================================

/// Basic LLM detector implementation
pub struct BasicLLMDetector {
    id: String,
    confidence_threshold: f64,
    supported_langs: Vec<String>,
    pattern_signatures: HashMap<String, Vec<String>>,
}

impl BasicLLMDetector {
    pub fn new() -> Self {
        Self {
            id: "basic_llm_detector".to_string(),
            confidence_threshold: 0.7,
            supported_langs: vec![
                "rust".to_string(),
                "javascript".to_string(),
                "python".to_string(),
            ],
            pattern_signatures: Self::default_signatures(),
        }
    }

    fn default_signatures() -> HashMap<String, Vec<String>> {
        let mut signatures = HashMap::new();

        // Common LLM-generated code patterns
        signatures.insert("generic_variables".to_string(), vec![
            "data".to_string(),
            "result".to_string(),
            "output".to_string(),
            "response".to_string(),
            "item".to_string(),
        ]);

        signatures.insert("verbose_comments".to_string(), vec![
            "// This function".to_string(),
            "// The purpose of this".to_string(),
            "// Here we are".to_string(),
            "// Let's".to_string(),
        ]);

        signatures.insert("boilerplate_patterns".to_string(), vec![
            "if __name__ == \"__main__\":".to_string(),
            "function main()".to_string(),
            "def main():".to_string(),
            "async function".to_string(),
        ]);

        signatures
    }

    fn analyze_token_patterns(&self, code: &str) -> f64 {
        let mut score: f64 = 0.0;

        for patterns in self.pattern_signatures.values() {
            for pattern in patterns {
                if code.contains(pattern) {
                    score += 0.1;
                }
            }
        }

        score.min(1.0)
    }
}

impl LLMDetector for BasicLLMDetector {
    fn detect_llm_signatures(&self, code: &str) -> anyhow::Result<DetectionResult> {
        let confidence = self.analyze_token_patterns(code);

        let evidence = vec![
            Evidence {
                evidence_type: EvidenceType::StatisticalAnomaly {
                    metric: "token_pattern_score".to_string(),
                    threshold: self.confidence_threshold,
                },
                location: CodeLocation {
                    file_path: None,
                    line_start: 1,
                    line_end: code.lines().count(),
                    column_start: 1,
                    column_end: 1,
                    context: Some("Full code analysis".to_string()),
                },
                signature: format!("token_pattern_{confidence:.3}"),
                confidence,
                metadata: HashMap::new(),
            }
        ];

        let provenance = Provenance {
            git_hash: None,
            build_id: "basic_llm_detector_v1".to_string(),
            timestamp: chrono::Utc::now(),
            analyzer_version: "0.1.0".to_string(),
            environment_fingerprint: "test_env".to_string(),
            input_hash: format!("{:x}", md5::compute(code)),
        };

        Ok(DetectionResult {
            pattern_id: Uuid::new_v4(),
            confidence,
            evidence,
            provenance,
            rationale: format!(
                "Detected {} LLM signature patterns with confidence {:.3}",
                self.pattern_signatures.len(),
                confidence
            ),
            ontology_tags: vec!["llm_generated".to_string(), "pattern_based".to_string()],
            detection_timestamp: chrono::Utc::now(),
        })
    }

    fn validate_confidence(&self, result: &DetectionResult) -> bool {
        result.confidence >= self.confidence_threshold
    }

    fn supported_languages(&self) -> Vec<String> {
        self.supported_langs.clone()
    }

    fn update_model(&mut self, training_data: &[TrainingExample]) -> anyhow::Result<()> {
        // Simple update mechanism for demonstration
        for example in training_data {
            if let CodeOrigin::LLMGenerated { signatures, .. } = &example.expected_origin {
                for sig in signatures {
                    self.pattern_signatures
                        .entry("learned_patterns".to_string())
                        .or_default()
                        .push(sig.clone());
                }
            }
        }
        Ok(())
    }
}

impl Default for BasicLLMDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternEngine for BasicLLMDetector {
    fn id(&self) -> &str {
        &self.id
    }

    fn analyze(&self, code: &str) -> anyhow::Result<Vec<DetectionResult>> {
        let detection = self.detect_llm_signatures(code)?;
        Ok(vec![detection])
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            supported_languages: self.supported_langs.clone(),
            pattern_types: vec!["llm_detection".to_string()],
            features: vec!["token_analysis".to_string(), "pattern_matching".to_string()],
            performance_characteristics: {
                let mut perf = HashMap::new();
                perf.insert("accuracy".to_string(), 0.7);
                perf.insert("speed".to_string(), 0.9);
                perf
            },
        }
    }

    fn update_patterns(&mut self, _patterns: &[DetectionOntology]) -> anyhow::Result<()> {
        Ok(())
    }

    fn performance_metrics(&self) -> PerformanceMetrics {
        PerformanceMetrics::default()
    }
}

impl AnalysisSession {
    /// Create a new analysis session
    pub fn new(investigator_id: String, case_id: String) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            started_at: chrono::Utc::now(),
            investigator_id,
            case_id,
            inputs: Vec::new(),
            results: Vec::new(),
            annotations: Vec::new(),
            reproducibility_hash: String::new(),
        }
    }

    /// Add input to the session
    pub fn add_input(&mut self, input: AnalysisInput) {
        self.inputs.push(input);
        self.update_reproducibility_hash();
    }

    /// Add detection result to the session
    pub fn add_result(&mut self, result: DetectionResult) {
        self.results.push(result);
        self.update_reproducibility_hash();
    }

    /// Add user annotation
    pub fn add_annotation(&mut self, annotation: UserAnnotation) {
        self.annotations.push(annotation);
        self.update_reproducibility_hash();
    }

    /// Update reproducibility hash
    fn update_reproducibility_hash(&mut self) {
        let session_data = serde_json::to_string(self).unwrap_or_default();
        self.reproducibility_hash = format!("{:x}", md5::compute(session_data));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_llm_detector() {
        let detector = BasicLLMDetector::new();

        // Test code with LLM patterns
        let llm_code = r#"
        def main():
            # This function processes the data
            data = get_data()
            result = process_data(data)
            return result
        "#;

        let result = detector.detect_llm_signatures(llm_code).unwrap();
        assert!(result.confidence > 0.0);
        assert!(detector.validate_confidence(&result));
    }

    #[test]
    fn test_analysis_session() {
        let mut session = AnalysisSession::new(
            "investigator_1".to_string(),
            "case_001".to_string(),
        );

        let input = AnalysisInput {
            input_id: Uuid::new_v4(),
            input_type: InputType::SourceCode {
                language: "rust".to_string(),
                file_path: "test.rs".to_string(),
            },
            content_hash: "hash123".to_string(),
            metadata: HashMap::new(),
        };

        session.add_input(input);
        assert_eq!(session.inputs.len(), 1);
        assert!(!session.reproducibility_hash.is_empty());
    }

    #[test]
    fn test_detection_result_serialization() {
        let result = DetectionResult {
            pattern_id: Uuid::new_v4(),
            confidence: 0.85,
            evidence: vec![],
            provenance: Provenance {
                git_hash: None,
                build_id: "test".to_string(),
                timestamp: chrono::Utc::now(),
                analyzer_version: "0.1.0".to_string(),
                environment_fingerprint: "test_env".to_string(),
                input_hash: "hash123".to_string(),
            },
            rationale: "Test detection".to_string(),
            ontology_tags: vec!["test".to_string()],
            detection_timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DetectionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.confidence, deserialized.confidence);
    }
}