use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionOntology {
    pub patterns: HashMap<String, PatternEntry>,
    pub evolution_tracker: EvolutionTracker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternEntry {
    pub id: String,
    pub pattern_type: String,
    pub semantic_tags: Vec<String>,
    pub provenance: PatternProvenance,
    pub confidence_model: ConfidenceModel,
    pub relationships: Vec<OntologyRelationship>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternProvenance {
    pub discovered_by: String,
    pub discovery_date: DateTime<Utc>,
    pub validation_status: ValidationStatus,
    pub threat_actor_attribution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationStatus {
    Validated,
    Experimental,
    Deprecated,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OntologyRelationship {
    Evolves { from: String, similarity: f64 },
    Combines { patterns: Vec<String> },
    Contradicts { pattern: String, resolution: String },
    Specializes { parent: String, domain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EvolutionTracker {
    pub pattern_mutations: Vec<PatternMutation>,
    pub confidence_drift: Vec<ConfidenceDrift>,
    pub false_positive_trends: Vec<FalsePositiveTrend>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternMutation {
    pub original_pattern: String,
    pub mutated_pattern: String,
    pub mutation_type: MutationType,
    pub first_observed: DateTime<Utc>,
    pub prevalence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MutationType {
    Obfuscation { technique: String },
    Fragmentation { fragment_count: usize },
    Hybridization { combined_with: Vec<String> },
    Adversarial { evasion_method: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceDrift {
    pub pattern_id: String,
    pub timestamp: DateTime<Utc>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FalsePositiveTrend {
    pub pattern_id: String,
    pub timestamp: DateTime<Utc>,
    pub false_positive_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceModel {
    pub base_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceMetrics {
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub accuracy: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub execution_time_ms: u64,
    pub memory_usage_mb: f64,
}

impl DetectionOntology {
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            evolution_tracker: EvolutionTracker::default(),
        }
    }

    pub fn add_pattern(&mut self, pattern: PatternEntry) -> Option<PatternEntry> {
        self.patterns.insert(pattern.id.clone(), pattern)
    }

    pub fn get_pattern(&self, id: &str) -> Option<&PatternEntry> {
        self.patterns.get(id)
    }
}

impl Default for DetectionOntology {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            precision: f64::NAN,
            recall: f64::NAN,
            f1_score: f64::NAN,
            accuracy: f64::NAN,
            false_positive_rate: f64::NAN,
            false_negative_rate: f64::NAN,
            execution_time_ms: 0,
            memory_usage_mb: f64::NAN,
        }
    }
}