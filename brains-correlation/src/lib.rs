//! # Brains Correlation
//! 
//! Fragment correlation and intent reconstruction for forensic analysis.
//! Implements reverse RASP techniques for automated threat intelligence assembly.

use brains_detection::DetectionResult;
use brains_forensics::PatternMatch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Fragment correlation engine for intent reconstruction
pub trait FragmentCorrelationEngine {
    fn correlate_fragments(&mut self, samples: &[CodeFragment]) -> anyhow::Result<CorrelationScore>;
    
    fn reconstruct_intent(&self, correlated: &CorrelationScore) -> anyhow::Result<Option<IntentGraph>>;
    
    fn detect_orchestration_patterns(&self, fragments: &[CodeFragment]) -> anyhow::Result<Vec<OrchestrationPattern>>;
    
    fn analyze_relationships(&self, fragments: &[CodeFragment]) -> anyhow::Result<Vec<FragmentRelationship>>;
}

/// Code fragment for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFragment {
    pub fragment_id: Uuid,
    pub content: String,
    pub source_file: String,
    pub line_range: (usize, usize),
    pub language: String,
    pub ast_hash: String,
    pub semantic_hash: String,
    pub pattern_matches: Vec<PatternMatch>,
    pub detection_results: Vec<DetectionResult>,
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Correlation score between fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationScore {
    pub correlation_id: Uuid,
    pub fragments: Vec<CodeFragment>,
    pub correlation_strength: f64,
    pub correlation_type: CorrelationType,
    pub evidence: Vec<CorrelationEvidence>,
    pub timeline: Vec<CorrelationEvent>,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

/// Types of correlation between fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    SemanticSimilarity { 
        threshold: f64,
        similarity_metrics: Vec<SimilarityMetric>,
    },
    StructuralMatch { 
        ast_similarity: f64,
        structural_features: Vec<String>,
    },
    ProvenanceLinked { 
        shared_indicators: Vec<String>,
        provenance_confidence: f64,
    },
    TemporalCorrelation { 
        time_window: chrono::Duration,
        temporal_patterns: Vec<String>,
    },
    IntentionAlignment { 
        intent_vector: Vec<f64>,
        alignment_score: f64,
    },
    FunctionalCoupling {
        coupling_strength: f64,
        shared_functions: Vec<String>,
    },
}

/// Similarity metric for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityMetric {
    pub metric_type: String,
    pub value: f64,
    pub weight: f64,
    pub description: String,
}

/// Evidence supporting correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEvidence {
    pub evidence_type: CorrelationEvidenceType,
    pub fragments: Vec<Uuid>,
    pub strength: f64,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

/// Types of correlation evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationEvidenceType {
    SharedStrings { strings: Vec<String> },
    SimilarPatterns { patterns: Vec<String> },
    CommonLibraries { libraries: Vec<String> },
    MatchingSignatures { signatures: Vec<String> },
    TemporalProximity { time_difference: chrono::Duration },
    StructuralSimilarity { similarity_score: f64 },
    ProvenanceMarkers { markers: Vec<String> },
}

/// Correlation event in timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEvent {
    pub event_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub fragments: Vec<Uuid>,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

/// Intent graph reconstructed from fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentGraph {
    pub graph_id: Uuid,
    pub nodes: Vec<IntentNode>,
    pub edges: Vec<IntentEdge>,
    pub overall_intent: OverallIntent,
    pub confidence: f64,
    pub reconstruction_method: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Node in intent graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentNode {
    pub node_id: Uuid,
    pub fragment_id: Uuid,
    pub intent_type: IntentType,
    pub capabilities: Vec<String>,
    pub risk_score: f64,
    pub confidence: f64,
    pub metadata: HashMap<String, String>,
}

/// Edge in intent graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentEdge {
    pub edge_id: Uuid,
    pub source_node: Uuid,
    pub target_node: Uuid,
    pub relationship_type: String,
    pub weight: f64,
    pub description: String,
}

/// Types of intent identified in fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentType {
    DataCollection { 
        targets: Vec<String>,
        collection_methods: Vec<String>,
    },
    NetworkCommunication { 
        endpoints: Vec<String>,
        protocols: Vec<String>,
    },
    Evasion { 
        techniques: Vec<String>,
        target_systems: Vec<String>,
    },
    Persistence { 
        mechanisms: Vec<String>,
        locations: Vec<String>,
    },
    Exfiltration { 
        channels: Vec<String>,
        data_types: Vec<String>,
    },
    Surveillance {
        monitoring_targets: Vec<String>,
        collection_scope: Vec<String>,
    },
    Exploitation {
        vulnerabilities: Vec<String>,
        attack_vectors: Vec<String>,
    },
}

/// Overall intent classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverallIntent {
    SurveillanceTool {
        tool_type: String,
        confidence: f64,
        capabilities: Vec<String>,
    },
    MalwareFamily {
        family_name: String,
        confidence: f64,
        characteristics: Vec<String>,
    },
    APTCampaign {
        campaign_name: String,
        confidence: f64,
        attribution: Vec<String>,
    },
    LegitimateToolkit {
        toolkit_type: String,
        confidence: f64,
        use_cases: Vec<String>,
    },
    Unknown {
        ambiguity_reasons: Vec<String>,
        potential_classifications: Vec<String>,
    },
}

/// Orchestration pattern detected across fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationPattern {
    pub pattern_id: Uuid,
    pub pattern_type: String,
    pub fragments: Vec<Uuid>,
    pub execution_order: Vec<Uuid>,
    pub coordination_method: String,
    pub confidence: f64,
    pub description: String,
}

/// Relationship between fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentRelationship {
    pub relationship_id: Uuid,
    pub source_fragment: Uuid,
    pub target_fragment: Uuid,
    pub relationship_type: RelationshipType,
    pub strength: f64,
    pub evidence: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Types of relationships between fragments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
    DependsOn { dependency_type: String },
    Calls { function_name: String },
    DataFlow { data_type: String },
    TemporalSequence { order: usize },
    SharedResource { resource_type: String },
    CompilationUnit { unit_type: String },
}

/// Advanced correlation engine implementation
pub struct AdvancedCorrelationEngine {
    similarity_threshold: f64,
    temporal_window: chrono::Duration,
    intent_classifiers: HashMap<String, Box<dyn IntentClassifier>>,
    correlation_cache: HashMap<String, CorrelationScore>,
}

/// Intent classifier trait
pub trait IntentClassifier {
    fn classify_intent(&self, fragment: &CodeFragment) -> anyhow::Result<IntentType>;
    fn confidence(&self, fragment: &CodeFragment) -> f64;
    fn supported_languages(&self) -> Vec<String>;
}

impl AdvancedCorrelationEngine {
    /// Create new correlation engine
    pub fn new() -> Self {
        let mut intent_classifiers: HashMap<String, Box<dyn IntentClassifier>> = HashMap::new();
        intent_classifiers.insert("surveillance".to_string(), Box::new(SurveillanceClassifier::new()));
        intent_classifiers.insert("malware".to_string(), Box::new(MalwareClassifier::new()));
        intent_classifiers.insert("data_collection".to_string(), Box::new(DataCollectionClassifier::new()));
        
        Self {
            similarity_threshold: 0.7,
            temporal_window: chrono::Duration::hours(24),
            intent_classifiers,
            correlation_cache: HashMap::new(),
        }
    }
    
    /// Calculate semantic similarity between fragments
    fn calculate_semantic_similarity(&self, frag1: &CodeFragment, frag2: &CodeFragment) -> f64 {
        // Simplified semantic similarity calculation
        let mut similarity = 0.0;
        
        // Pattern match similarity
        let pattern_overlap = self.calculate_pattern_overlap(frag1, frag2);
        similarity += pattern_overlap * 0.4;
        
        // String similarity
        let string_similarity = self.calculate_string_similarity(&frag1.content, &frag2.content);
        similarity += string_similarity * 0.3;
        
        // AST similarity
        let ast_similarity = self.calculate_ast_similarity(frag1, frag2);
        similarity += ast_similarity * 0.3;
        
        similarity
    }
    
    /// Calculate pattern overlap between fragments
    fn calculate_pattern_overlap(&self, frag1: &CodeFragment, frag2: &CodeFragment) -> f64 {
        let patterns1: std::collections::HashSet<_> = frag1.pattern_matches.iter()
            .map(|p| &p.pattern_name)
            .collect();
        let patterns2: std::collections::HashSet<_> = frag2.pattern_matches.iter()
            .map(|p| &p.pattern_name)
            .collect();
        
        let intersection = patterns1.intersection(&patterns2).count();
        let union = patterns1.union(&patterns2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }
    
    /// Calculate string similarity using simple metrics
    fn calculate_string_similarity(&self, str1: &str, str2: &str) -> f64 {
        // Simple Jaccard similarity on words
        let words1: std::collections::HashSet<_> = str1.split_whitespace().collect();
        let words2: std::collections::HashSet<_> = str2.split_whitespace().collect();
        
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }
    
    /// Calculate AST similarity using hashes
    fn calculate_ast_similarity(&self, frag1: &CodeFragment, frag2: &CodeFragment) -> f64 {
        if frag1.ast_hash == frag2.ast_hash {
            1.0
        } else {
            // Simple hash comparison - in practice, use more sophisticated AST diff
            let hash1_bytes = hex::decode(&frag1.ast_hash).unwrap_or_default();
            let hash2_bytes = hex::decode(&frag2.ast_hash).unwrap_or_default();
            
            if hash1_bytes.len() != hash2_bytes.len() {
                return 0.0;
            }
            
            let matching_bytes = hash1_bytes.iter()
                .zip(hash2_bytes.iter())
                .filter(|(a, b)| a == b)
                .count();
            
            matching_bytes as f64 / hash1_bytes.len() as f64
        }
    }
    
    /// Generate cache key for correlation
    fn generate_cache_key(&self, fragments: &[CodeFragment]) -> String {
        let mut hasher = Sha256::new();
        for fragment in fragments {
            hasher.update(fragment.fragment_id.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

impl FragmentCorrelationEngine for AdvancedCorrelationEngine {
    fn correlate_fragments(&mut self, samples: &[CodeFragment]) -> anyhow::Result<CorrelationScore> {
        let cache_key = self.generate_cache_key(samples);
        
        if let Some(cached_score) = self.correlation_cache.get(&cache_key) {
            return Ok(cached_score.clone());
        }
        
        let mut evidence = Vec::new();
        let mut timeline = Vec::new();
        let mut overall_strength = 0.0;
        let correlation_type = CorrelationType::SemanticSimilarity {
            threshold: self.similarity_threshold,
            similarity_metrics: Vec::new(),
        };
        
        if samples.len() <= 50 {
            for (i, frag1) in samples.iter().enumerate() {
                for (j, frag2) in samples.iter().enumerate() {
                    if i >= j { continue; }
                    
                    let similarity = self.calculate_semantic_similarity(frag1, frag2);
                    if similarity > self.similarity_threshold {
                        evidence.push(CorrelationEvidence {
                            evidence_type: CorrelationEvidenceType::StructuralSimilarity {
                                similarity_score: similarity,
                            },
                            fragments: vec![frag1.fragment_id, frag2.fragment_id],
                            strength: similarity,
                            description: format!("High semantic similarity: {similarity:.3}"),
                            metadata: HashMap::new(),
                        });
                        
                        overall_strength += similarity;
                    }
                    
                    let time_diff = (frag1.created_at - frag2.created_at).abs();
                    if time_diff < self.temporal_window {
                        timeline.push(CorrelationEvent {
                            event_id: Uuid::new_v4(),
                            timestamp: frag1.created_at.min(frag2.created_at),
                            event_type: "temporal_proximity".to_string(),
                            fragments: vec![frag1.fragment_id, frag2.fragment_id],
                            description: format!("Fragments created within {} minutes", time_diff.num_minutes()),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        } else {
            let mut sorted_fragments = samples.to_vec();
            sorted_fragments.sort_by_key(|f| f.semantic_hash.clone());
            
            for window in sorted_fragments.windows(2) {
                let frag1 = &window[0];
                let frag2 = &window[1];
                
                let similarity = self.calculate_semantic_similarity(frag1, frag2);
                if similarity > self.similarity_threshold {
                    evidence.push(CorrelationEvidence {
                        evidence_type: CorrelationEvidenceType::StructuralSimilarity {
                            similarity_score: similarity,
                        },
                        fragments: vec![frag1.fragment_id, frag2.fragment_id],
                        strength: similarity,
                        description: format!("Adjacent similarity: {similarity:.3}"),
                        metadata: HashMap::new(),
                    });
                    
                    overall_strength += similarity;
                }
            }
        }
        
        let pair_count = if samples.len() <= 50 {
            (samples.len() * (samples.len() - 1)) / 2
        } else {
            samples.len().saturating_sub(1)
        };
        if pair_count > 0 {
            overall_strength /= pair_count as f64;
        }
        
        let score = CorrelationScore {
            correlation_id: Uuid::new_v4(),
            fragments: samples.to_vec(),
            correlation_strength: overall_strength,
            correlation_type,
            evidence,
            timeline,
            confidence: if overall_strength > 0.8 { 0.9 } else { overall_strength },
            metadata: HashMap::new(),
        };
        
        self.correlation_cache.insert(cache_key, score.clone());
        
        Ok(score)
    }
    
    fn reconstruct_intent(&self, correlated: &CorrelationScore) -> anyhow::Result<Option<IntentGraph>> {
        if correlated.correlation_strength < 0.5 {
            return Ok(None);
        }
        
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        
        // Classify intent for each fragment
        for fragment in &correlated.fragments {
            let mut intent_type = IntentType::DataCollection {
                targets: vec!["unknown".to_string()],
                collection_methods: vec!["analysis".to_string()],
            };
            let mut confidence = 0.5;
            
            // Try different classifiers
            for (_classifier_name, classifier) in &self.intent_classifiers {
                let fragment_confidence = classifier.confidence(fragment);
                if fragment_confidence > confidence {
                    intent_type = classifier.classify_intent(fragment)?;
                    confidence = fragment_confidence;
                }
            }
            
            nodes.push(IntentNode {
                node_id: Uuid::new_v4(),
                fragment_id: fragment.fragment_id,
                intent_type,
                capabilities: fragment.pattern_matches.iter()
                    .map(|p| p.pattern_name.clone())
                    .collect(),
                risk_score: confidence * 0.8,
                confidence,
                metadata: HashMap::new(),
            });
        }
        
        // Create edges based on correlation evidence
        for evidence in &correlated.evidence {
            if evidence.fragments.len() == 2 {
                let source_node = nodes.iter()
                    .find(|n| n.fragment_id == evidence.fragments[0])
                    .map(|n| n.node_id);
                let target_node = nodes.iter()
                    .find(|n| n.fragment_id == evidence.fragments[1])
                    .map(|n| n.node_id);
                
                if let (Some(source), Some(target)) = (source_node, target_node) {
                    edges.push(IntentEdge {
                        edge_id: Uuid::new_v4(),
                        source_node: source,
                        target_node: target,
                        relationship_type: "correlation".to_string(),
                        weight: evidence.strength,
                        description: evidence.description.clone(),
                    });
                }
            }
        }
        
        // Determine overall intent
        let overall_intent = self.classify_overall_intent(&nodes)?;
        
        Ok(Some(IntentGraph {
            graph_id: Uuid::new_v4(),
            nodes,
            edges,
            overall_intent,
            confidence: correlated.confidence,
            reconstruction_method: "advanced_correlation".to_string(),
            created_at: chrono::Utc::now(),
        }))
    }
    
    fn detect_orchestration_patterns(&self, fragments: &[CodeFragment]) -> anyhow::Result<Vec<OrchestrationPattern>> {
        let mut patterns = Vec::new();
        
        // Look for sequential execution patterns
        let mut sequential_fragments = fragments.to_vec();
        sequential_fragments.sort_by_key(|f| f.created_at);
        
        if sequential_fragments.len() > 2 {
            patterns.push(OrchestrationPattern {
                pattern_id: Uuid::new_v4(),
                pattern_type: "sequential_execution".to_string(),
                fragments: sequential_fragments.iter().map(|f| f.fragment_id).collect(),
                execution_order: sequential_fragments.iter().map(|f| f.fragment_id).collect(),
                coordination_method: "temporal_sequence".to_string(),
                confidence: 0.7,
                description: "Sequential execution pattern detected".to_string(),
            });
        }
        
        // Look for data flow patterns
        // This would be more sophisticated in a real implementation
        patterns.push(OrchestrationPattern {
            pattern_id: Uuid::new_v4(),
            pattern_type: "data_flow".to_string(),
            fragments: fragments.iter().map(|f| f.fragment_id).collect(),
            execution_order: Vec::new(),
            coordination_method: "data_dependencies".to_string(),
            confidence: 0.6,
            description: "Data flow orchestration pattern".to_string(),
        });
        
        Ok(patterns)
    }
    
    fn analyze_relationships(&self, fragments: &[CodeFragment]) -> anyhow::Result<Vec<FragmentRelationship>> {
        let mut relationships = Vec::new();
        
        for (i, frag1) in fragments.iter().enumerate() {
            for (j, frag2) in fragments.iter().enumerate() {
                if i >= j { continue; }
                
                // Temporal relationship
                if frag1.created_at < frag2.created_at {
                    relationships.push(FragmentRelationship {
                        relationship_id: Uuid::new_v4(),
                        source_fragment: frag1.fragment_id,
                        target_fragment: frag2.fragment_id,
                        relationship_type: RelationshipType::TemporalSequence { order: j - i },
                        strength: 0.8,
                        evidence: vec!["temporal_ordering".to_string()],
                        metadata: HashMap::new(),
                    });
                }
                
                // Similarity relationship
                let similarity = self.calculate_semantic_similarity(frag1, frag2);
                if similarity > 0.7 {
                    relationships.push(FragmentRelationship {
                        relationship_id: Uuid::new_v4(),
                        source_fragment: frag1.fragment_id,
                        target_fragment: frag2.fragment_id,
                        relationship_type: RelationshipType::SharedResource {
                            resource_type: "semantic_similarity".to_string(),
                        },
                        strength: similarity,
                        evidence: vec!["high_similarity".to_string()],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        Ok(relationships)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_fragment(id: &str, content: &str) -> CodeFragment {
        CodeFragment {
            fragment_id: Uuid::new_v4(),
            content: content.to_string(),
            source_file: format!("test_{}.rs", id),
            line_range: (1, 10),
            language: "rust".to_string(),
            ast_hash: "test_ast_hash".to_string(),
            semantic_hash: "test_semantic_hash".to_string(),
            pattern_matches: Vec::new(),
            detection_results: Vec::new(),
            metadata: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_cache_functionality() {
        let mut engine = AdvancedCorrelationEngine::new();
        let fragments = vec![
            create_test_fragment("1", "fn test() { println!(\"hello\"); }"),
            create_test_fragment("2", "fn test() { println!(\"world\"); }"),
        ];

        let result1 = engine.correlate_fragments(&fragments).unwrap();
        let cache_key = engine.generate_cache_key(&fragments);
        
        assert!(engine.correlation_cache.get(&cache_key).is_some(), "Cache should contain result after first computation");
        
        let result2 = engine.correlate_fragments(&fragments).unwrap();
        assert_eq!(result1.correlation_id, result2.correlation_id, "Cached results should be identical");
    }

    #[test] 
    fn test_pairwise_performance() {
        let engine = AdvancedCorrelationEngine::new();
        let fragments: Vec<CodeFragment> = (0..100)
            .map(|i| create_test_fragment(&i.to_string(), &format!("fn test_{}() {{}}", i)))
            .collect();

        let start = std::time::Instant::now();
        let _result = engine.correlate_fragments(&fragments).unwrap();
        let duration = start.elapsed();
        
        assert!(duration.as_millis() < 1000, "O(n²) algorithm too slow for 100 fragments: {:?}", duration);
    }
}

impl AdvancedCorrelationEngine {
    /// Classify overall intent from individual intents
    fn classify_overall_intent(&self, nodes: &[IntentNode]) -> anyhow::Result<OverallIntent> {
        let mut intent_counts = HashMap::new();
        let mut total_confidence = 0.0;
        
        for node in nodes {
            let intent_key = match &node.intent_type {
                IntentType::DataCollection { .. } => "data_collection",
                IntentType::NetworkCommunication { .. } => "network_communication",
                IntentType::Surveillance { .. } => "surveillance",
                IntentType::Evasion { .. } => "evasion",
                IntentType::Persistence { .. } => "persistence",
                IntentType::Exfiltration { .. } => "exfiltration",
                IntentType::Exploitation { .. } => "exploitation",
            };
            
            *intent_counts.entry(intent_key).or_insert(0) += 1;
            total_confidence += node.confidence;
        }
        
        let avg_confidence = if nodes.is_empty() { 0.0 } else { total_confidence / nodes.len() as f64 };
        
        // Classify based on dominant intent
        if let Some((dominant_intent, _)) = intent_counts.iter().max_by_key(|(_, count)| *count) {
            match *dominant_intent {
                "surveillance" | "data_collection" => {
                    Ok(OverallIntent::SurveillanceTool {
                        tool_type: "data_collection_suite".to_string(),
                        confidence: avg_confidence,
                        capabilities: nodes.iter().flat_map(|n| n.capabilities.clone()).collect(),
                    })
                }
                "evasion" | "persistence" | "exfiltration" => {
                    Ok(OverallIntent::MalwareFamily {
                        family_name: "advanced_persistent_threat".to_string(),
                        confidence: avg_confidence,
                        characteristics: nodes.iter().flat_map(|n| n.capabilities.clone()).collect(),
                    })
                }
                _ => {
                    Ok(OverallIntent::Unknown {
                        ambiguity_reasons: vec!["insufficient_evidence".to_string()],
                        potential_classifications: intent_counts.keys().map(|k| k.to_string()).collect(),
                    })
                }
            }
        } else {
            Ok(OverallIntent::Unknown {
                ambiguity_reasons: vec!["no_clear_intent".to_string()],
                potential_classifications: Vec::new(),
            })
        }
    }
}

impl CodeFragment {
    /// Create new code fragment
    pub fn new(content: String, source_file: String, language: String) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let content_hash = hex::encode(hasher.finalize());
        
        Self {
            fragment_id: Uuid::new_v4(),
            content,
            source_file,
            line_range: (1, 1),
            language,
            ast_hash: content_hash.clone(),
            semantic_hash: content_hash,
            pattern_matches: Vec::new(),
            detection_results: Vec::new(),
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }
}

/// Surveillance-specific intent classifier
pub struct SurveillanceClassifier;

impl SurveillanceClassifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SurveillanceClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentClassifier for SurveillanceClassifier {
    fn classify_intent(&self, fragment: &CodeFragment) -> anyhow::Result<IntentType> {
        // Look for surveillance-specific patterns
        if fragment.content.contains("collect") || fragment.content.contains("monitor") {
            Ok(IntentType::Surveillance {
                monitoring_targets: vec!["user_activity".to_string()],
                collection_scope: vec!["network_traffic".to_string()],
            })
        } else if fragment.content.contains("query") || fragment.content.contains("search") {
            Ok(IntentType::DataCollection {
                targets: vec!["database".to_string()],
                collection_methods: vec!["query".to_string()],
            })
        } else {
            Ok(IntentType::DataCollection {
                targets: vec!["unknown".to_string()],
                collection_methods: vec!["analysis".to_string()],
            })
        }
    }
    
    fn confidence(&self, fragment: &CodeFragment) -> f64 {
        let surveillance_keywords = ["collect", "monitor", "query", "search", "intercept", "surveillance"];
        let keyword_count = surveillance_keywords.iter()
            .filter(|&keyword| fragment.content.contains(keyword))
            .count();
        
        (keyword_count as f64 / surveillance_keywords.len() as f64).min(1.0)
    }
    
    fn supported_languages(&self) -> Vec<String> {
        vec!["rust".to_string(), "javascript".to_string(), "python".to_string()]
    }
}

/// Malware-specific intent classifier
pub struct MalwareClassifier;

impl MalwareClassifier {
    pub fn new() -> Self {
        Self
    }
}

impl IntentClassifier for MalwareClassifier {
    fn classify_intent(&self, fragment: &CodeFragment) -> anyhow::Result<IntentType> {
        if fragment.content.contains("persistence") || fragment.content.contains("registry") {
            Ok(IntentType::Persistence {
                mechanisms: vec!["registry".to_string()],
                locations: vec!["startup".to_string()],
            })
        } else if fragment.content.contains("exfiltrate") || fragment.content.contains("upload") {
            Ok(IntentType::Exfiltration {
                channels: vec!["network".to_string()],
                data_types: vec!["files".to_string()],
            })
        } else {
            Ok(IntentType::Exploitation {
                vulnerabilities: vec!["unknown".to_string()],
                attack_vectors: vec!["code_injection".to_string()],
            })
        }
    }
    
    fn confidence(&self, fragment: &CodeFragment) -> f64 {
        let malware_keywords = ["persistence", "registry", "exfiltrate", "upload", "inject", "exploit"];
        let keyword_count = malware_keywords.iter()
            .filter(|&keyword| fragment.content.contains(keyword))
            .count();
        
        (keyword_count as f64 / malware_keywords.len() as f64).min(1.0)
    }
    
    fn supported_languages(&self) -> Vec<String> {
        vec!["rust".to_string(), "javascript".to_string(), "python".to_string(), "c".to_string()]
    }
}

/// Data collection intent classifier
pub struct DataCollectionClassifier;

impl DataCollectionClassifier {
    pub fn new() -> Self {
        Self
    }
}

impl IntentClassifier for DataCollectionClassifier {
    fn classify_intent(&self, fragment: &CodeFragment) -> anyhow::Result<IntentType> {
        Ok(IntentType::DataCollection {
            targets: vec!["user_data".to_string()],
            collection_methods: vec!["api_calls".to_string()],
        })
    }
    
    fn confidence(&self, fragment: &CodeFragment) -> f64 {
        let data_keywords = ["collect", "gather", "retrieve", "fetch", "get"];
        let keyword_count = data_keywords.iter()
            .filter(|&keyword| fragment.content.contains(keyword))
            .count();
        
        (keyword_count as f64 / data_keywords.len() as f64).min(1.0)
    }
    
    fn supported_languages(&self) -> Vec<String> {
        vec!["rust".to_string(), "javascript".to_string(), "python".to_string()]
    }
}

impl Default for AdvancedCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_creation() {
        let fragment = CodeFragment::new(
            "fn collect_data() { println!(\"collecting\"); }".to_string(),
            "test.rs".to_string(),
            "rust".to_string(),
        );
        
        assert!(!fragment.content.is_empty());
        assert_eq!(fragment.language, "rust");
        assert!(!fragment.ast_hash.is_empty());
    }
    
    #[test]
    fn test_correlation_engine() {
        let engine = AdvancedCorrelationEngine::new();
        
        let fragment1 = CodeFragment::new(
            "fn collect_data() { monitor_user(); }".to_string(),
            "module1.rs".to_string(),
            "rust".to_string(),
        );
        
        let fragment2 = CodeFragment::new(
            "fn collect_info() { monitor_system(); }".to_string(),
            "module2.rs".to_string(),
            "rust".to_string(),
        );
        
        let fragments = vec![fragment1, fragment2];
        let correlation = engine.correlate_fragments(&fragments).unwrap();
        
        assert_eq!(correlation.fragments.len(), 2);
        assert!(correlation.correlation_strength >= 0.0);
        assert!(correlation.correlation_strength <= 1.0);
    }
    
    #[test]
    fn test_intent_reconstruction() {
        let engine = AdvancedCorrelationEngine::new();
        
        let fragment1 = CodeFragment::new(
            "fn collect_surveillance_data() { monitor_user(); }".to_string(),
            "surveillance.rs".to_string(),
            "rust".to_string(),
        );
        
        let fragment2 = CodeFragment::new(
            "fn query_database() { search_records(); }".to_string(),
            "database.rs".to_string(),
            "rust".to_string(),
        );
        
        let fragments = vec![fragment1, fragment2];
        let correlation = engine.correlate_fragments(&fragments).unwrap();
        let intent_graph = engine.reconstruct_intent(&correlation).unwrap();
        
        assert!(intent_graph.is_some());
        let graph = intent_graph.unwrap();
        assert_eq!(graph.nodes.len(), 2);
        assert!(graph.confidence > 0.0);
    }
    
    #[test]
    fn test_surveillance_classifier() {
        let classifier = SurveillanceClassifier::new();
        
        let fragment = CodeFragment::new(
            "fn monitor_user_activity() { collect_data(); }".to_string(),
            "monitor.rs".to_string(),
            "rust".to_string(),
        );
        
        let intent = classifier.classify_intent(&fragment).unwrap();
        let confidence = classifier.confidence(&fragment);
        
        assert!(matches!(intent, IntentType::Surveillance { .. }));
        assert!(confidence > 0.0);
    }
    
    #[test]
    fn test_orchestration_detection() {
        let engine = AdvancedCorrelationEngine::new();
        
        let fragment1 = CodeFragment::new(
            "fn step1() { initialize(); }".to_string(),
            "step1.rs".to_string(),
            "rust".to_string(),
        );
        
        let mut fragment2 = CodeFragment::new(
            "fn step2() { process(); }".to_string(),
            "step2.rs".to_string(),
            "rust".to_string(),
        );
        fragment2.created_at = chrono::Utc::now() + chrono::Duration::seconds(1);
        
        let fragments = vec![fragment1, fragment2];
        let patterns = engine.detect_orchestration_patterns(&fragments).unwrap();
        
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.pattern_type == "sequential_execution"));
    }
}