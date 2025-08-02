//! Signed forensic reports with cryptographic chain of custody
//! 
//! This module provides forensic-grade reporting capabilities with cryptographic
//! integrity verification, chain of custody tracking, and legal admissibility support.

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

pub mod chain_of_custody;
pub mod report_schema;
pub mod signature;
pub mod templates;
pub mod validation;

/// Forensic report with cryptographic signatures and chain of custody
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub report_id: Uuid,
    pub report_type: ReportType,
    pub version: String,
    pub title: String,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub investigator: Investigator,
    pub case_info: CaseInfo,
    pub methodology: Methodology,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
    pub conclusions: Vec<Conclusion>,
    pub recommendations: Vec<Recommendation>,
    pub appendices: Vec<Appendix>,
    pub chain_of_custody: chain_of_custody::ChainOfCustody,
    pub signatures: Vec<signature::ReportSignature>,
    pub integrity_hash: String,
    pub schema_version: String,
}

/// Types of forensic reports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportType {
    LLMDetectionAnalysis,
    SurveillanceCodeAnalysis,
    PatternCorrelationReport,
    ProvenanceAnalysis,
    IncidentResponse,
    ThreatAssessment,
    ComplianceAudit,
    Custom(String),
}

/// Investigator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigator {
    pub investigator_id: Uuid,
    pub name: String,
    pub title: String,
    pub organization: String,
    pub credentials: Vec<String>,
    pub contact_info: ContactInfo,
    pub security_clearance: Option<String>,
    pub certification_date: Option<DateTime<Utc>>,
}

/// Contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub email: String,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub public_key: Option<String>,
}

/// Case information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub case_id: String,
    pub case_name: String,
    pub case_type: String,
    pub jurisdiction: String,
    pub classification: ClassificationLevel,
    pub request_date: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    pub requesting_party: String,
    pub legal_authority: Option<String>,
    pub related_cases: Vec<String>,
}

/// Classification levels for reports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClassificationLevel {
    Public,
    Internal,
    Restricted,
    Confidential,
    Secret,
    TopSecret,
}

/// Investigation methodology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Methodology {
    pub approach: String,
    pub tools_used: Vec<ToolUsage>,
    pub techniques: Vec<Technique>,
    pub standards_followed: Vec<String>,
    pub limitations: Vec<String>,
    pub assumptions: Vec<String>,
    pub validation_methods: Vec<String>,
}

/// Tool usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsage {
    pub tool_name: String,
    pub tool_version: String,
    pub purpose: String,
    pub configuration: HashMap<String, serde_json::Value>,
    pub execution_context: String,
}

/// Investigation technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub technique_name: String,
    pub description: String,
    pub rationale: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub validation_criteria: Vec<String>,
}

/// Investigation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: Uuid,
    pub finding_type: String,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub technical_details: String,
    pub evidence_references: Vec<Uuid>,
    pub supporting_data: serde_json::Value,
    pub implications: Vec<String>,
    pub mitigation_recommendations: Vec<String>,
    pub timeline: Option<Timeline>,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Timeline information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration: Option<String>,
    pub key_events: Vec<TimelineEvent>,
}

/// Timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub evidence_id: Option<Uuid>,
    pub confidence: f64,
}

/// Digital evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: Uuid,
    pub evidence_type: String,
    pub description: String,
    pub source: String,
    pub collection_method: String,
    pub collection_time: DateTime<Utc>,
    pub collector: String,
    pub hash_md5: String,
    pub hash_sha256: String,
    pub file_size: u64,
    pub file_path: Option<String>,
    pub preservation_method: String,
    pub chain_of_custody_id: Uuid,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Investigation conclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conclusion {
    pub conclusion_id: Uuid,
    pub conclusion_type: String,
    pub summary: String,
    pub supporting_findings: Vec<Uuid>,
    pub confidence: f64,
    pub legal_implications: Vec<String>,
    pub technical_impact: Vec<String>,
    pub business_impact: Vec<String>,
}

/// Recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub recommendation_id: Uuid,
    pub recommendation_type: String,
    pub priority: Priority,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub implementation_steps: Vec<String>,
    pub timeline: Option<String>,
    pub cost_estimate: Option<String>,
    pub risk_if_not_implemented: String,
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
    Immediate,
}

/// Report appendix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appendix {
    pub appendix_id: Uuid,
    pub title: String,
    pub content_type: String,
    pub content: serde_json::Value,
    pub description: String,
    pub file_reference: Option<String>,
}

impl ForensicReport {
    /// Create new forensic report
    pub fn new(
        report_type: ReportType,
        title: String,
        investigator: Investigator,
        case_info: CaseInfo,
    ) -> Self {
        let report_id = Uuid::new_v4();
        let now = Utc::now();
        
        let mut report = Self {
            report_id,
            report_type,
            version: "1.0".to_string(),
            title,
            summary: String::new(),
            created_at: now,
            updated_at: now,
            investigator,
            case_info,
            methodology: Methodology {
                approach: String::new(),
                tools_used: Vec::new(),
                techniques: Vec::new(),
                standards_followed: Vec::new(),
                limitations: Vec::new(),
                assumptions: Vec::new(),
                validation_methods: Vec::new(),
            },
            findings: Vec::new(),
            evidence: Vec::new(),
            conclusions: Vec::new(),
            recommendations: Vec::new(),
            appendices: Vec::new(),
            chain_of_custody: chain_of_custody::ChainOfCustody::new(report_id),
            signatures: Vec::new(),
            integrity_hash: String::new(),
            schema_version: "1.0.0".to_string(),
        };
        
        // Calculate initial integrity hash
        report.update_integrity_hash();
        
        report
    }
    
    /// Update integrity hash
    pub fn update_integrity_hash(&mut self) {
        self.updated_at = Utc::now();
        
        // Create hashable representation without signatures and hash
        let mut report_copy = self.clone();
        report_copy.signatures.clear();
        report_copy.integrity_hash.clear();
        
        let serialized = serde_json::to_string(&report_copy)
            .expect("Failed to serialize report");
        
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash = hasher.finalize();
        
        self.integrity_hash = hex::encode(hash);
    }
    
    /// Sign report with keypair
    pub fn sign(&mut self, keypair: &SigningKey, signer_role: String) -> Result<()> {
        use signature::ReportSignature;
        
        // Update hash before signing
        self.update_integrity_hash();
        
        // Create signature with deterministic preimage aligned to verify_signature():
        // format!("{}{}{}", report_id, signed_hash, signed_at.timestamp())
        let signed_at = Utc::now();
        let signature_data = format!("{}{}{}",
            self.report_id,
            self.integrity_hash,
            signed_at.timestamp()
        );
            self.updated_at.timestamp()
        );
        
        let signature = keypair.sign(signature_data.as_bytes());
        
        let report_signature = ReportSignature {
            signature_id: Uuid::new_v4(),
            public_key: hex::encode(keypair.verifying_key().to_bytes()),
            signature: hex::encode(signature.to_bytes()),
            signature_algorithm: "Ed25519".to_string(),
            signed_at,
            signer_role,
            signature_purpose: "Report Validation".to_string(),
            hash_algorithm: "SHA256".to_string(),
            signed_hash: self.integrity_hash.clone(),
        };
        
        self.signatures.push(report_signature);
        
        Ok(())
    }
    
    /// Verify all signatures
    pub fn verify_signatures(&self) -> Result<bool> {
        if self.signatures.is_empty() {
            return Ok(false);
        }
        
        for signature in &self.signatures {
            if !self.verify_signature(signature)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verify single signature
    pub fn verify_signature(&self, signature: &signature::ReportSignature) -> Result<bool> {
        // Reconstruct signature data
        let signature_data = format!("{}{}{}", 
            self.report_id, 
            signature.signed_hash, 
            signature.signed_at.timestamp()
        );
        
        // Decode public key and signature
        let public_key_bytes = hex::decode(&signature.public_key)?;
        let signature_bytes = hex::decode(&signature.signature)?;
        
        let public_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid public key length"))?)?;
        let sig = Signature::from_bytes(&signature_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signature length"))?);
        
        // Verify signature
        match public_key.verify(signature_data.as_bytes(), &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Add finding to report
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
        self.update_integrity_hash();
    }
    
    /// Add evidence to report
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
        self.update_integrity_hash();
    }
    
    /// Add conclusion to report
    pub fn add_conclusion(&mut self, conclusion: Conclusion) {
        self.conclusions.push(conclusion);
        self.update_integrity_hash();
    }
    
    /// Add recommendation to report
    pub fn add_recommendation(&mut self, recommendation: Recommendation) {
        self.recommendations.push(recommendation);
        self.update_integrity_hash();
    }
    
    /// Export report as JSON
    pub fn to_json(&self) -> Result<String> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(json)
    }
    
    /// Import report from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        let report: ForensicReport = serde_json::from_str(json)?;
        Ok(report)
    }
    
    /// Export report as YAML
    pub fn to_yaml(&self) -> Result<String> {
        let yaml = serde_yaml::to_string(self)?;
        Ok(yaml)
    }
    
    /// Import report from YAML
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let report: ForensicReport = serde_yaml::from_str(yaml)?;
        Ok(report)
    }
    
    /// Validate report integrity
    pub fn validate_integrity(&self) -> Result<bool> {
        // Create copy without signatures and hash
        let mut report_copy = self.clone();
        report_copy.signatures.clear();
        report_copy.integrity_hash.clear();
        
        // Recalculate hash
        let serialized = serde_json::to_string(&report_copy)?;
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let calculated_hash = hex::encode(hasher.finalize());
        
        // Compare with stored hash
        Ok(calculated_hash == self.integrity_hash)
    }
    
    /// Get report summary statistics
    pub fn get_statistics(&self) -> ReportStatistics {
        let total_findings = self.findings.len();
        let critical_findings = self.findings.iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_findings = self.findings.iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        
        let total_evidence = self.evidence.len();
        let total_conclusions = self.conclusions.len();
        let total_recommendations = self.recommendations.len();
        
        let signature_count = self.signatures.len();
        let is_signed = !self.signatures.is_empty();
        
        ReportStatistics {
            total_findings,
            critical_findings,
            high_findings,
            total_evidence,
            total_conclusions,
            total_recommendations,
            signature_count,
            is_signed,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Report statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatistics {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub total_evidence: usize,
    pub total_conclusions: usize,
    pub total_recommendations: usize,
    pub signature_count: usize,
    pub is_signed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    fn create_test_investigator() -> Investigator {
        Investigator {
            investigator_id: Uuid::new_v4(),
            name: "Dr. Jane Smith".to_string(),
            title: "Senior Forensic Analyst".to_string(),
            organization: "Digital Forensics Lab".to_string(),
            credentials: vec!["CISSP".to_string(), "GCFA".to_string()],
            contact_info: ContactInfo {
                email: "jane.smith@example.com".to_string(),
                phone: Some("+1-555-0123".to_string()),
                address: None,
                public_key: None,
            },
            security_clearance: Some("Secret".to_string()),
            certification_date: Some(Utc::now()),
        }
    }
    
    fn create_test_case() -> CaseInfo {
        CaseInfo {
            case_id: "CASE-2024-001".to_string(),
            case_name: "LLM Malware Detection".to_string(),
            case_type: "Digital Forensics".to_string(),
            jurisdiction: "Federal".to_string(),
            classification: ClassificationLevel::Restricted,
            request_date: Utc::now(),
            deadline: Some(Utc::now() + chrono::Duration::days(30)),
            requesting_party: "Cybersecurity Division".to_string(),
            legal_authority: Some("Court Order #2024-001".to_string()),
            related_cases: Vec::new(),
        }
    }

    #[test]
    fn test_report_creation() {
        let investigator = create_test_investigator();
        let case_info = create_test_case();
        
        let report = ForensicReport::new(
            ReportType::LLMDetectionAnalysis,
            "Test LLM Detection Report".to_string(),
            investigator,
            case_info,
        );
        
        assert_eq!(report.report_type, ReportType::LLMDetectionAnalysis);
        assert_eq!(report.title, "Test LLM Detection Report");
        assert!(!report.integrity_hash.is_empty());
    }
    
    #[test]
    fn test_report_signing() {
        let investigator = create_test_investigator();
        let case_info = create_test_case();
        
        let mut report = ForensicReport::new(
            ReportType::LLMDetectionAnalysis,
            "Test Report".to_string(),
            investigator,
            case_info,
        );
        
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        
        report.sign(&keypair, "Primary Investigator".to_string()).unwrap();
        
        assert_eq!(report.signatures.len(), 1);
        assert!(report.verify_signatures().unwrap());
    }
    
    #[test]
    fn test_integrity_validation() {
        let investigator = create_test_investigator();
        let case_info = create_test_case();
        
        let mut report = ForensicReport::new(
            ReportType::LLMDetectionAnalysis,
            "Test Report".to_string(),
            investigator,
            case_info,
        );
        
        // Should be valid initially
        assert!(report.validate_integrity().unwrap());
        
        // Add finding and verify hash updates
        let finding = Finding {
            finding_id: Uuid::new_v4(),
            finding_type: "LLM Detection".to_string(),
            severity: Severity::High,
            confidence: 0.95,
            title: "Suspicious LLM-generated code detected".to_string(),
            description: "Analysis indicates high probability of LLM generation".to_string(),
            technical_details: "Token entropy analysis shows characteristic patterns".to_string(),
            evidence_references: Vec::new(),
            supporting_data: serde_json::json!({}),
            implications: vec!["Potential surveillance tool".to_string()],
            mitigation_recommendations: vec!["Further analysis required".to_string()],
            timeline: None,
        };
        
        report.add_finding(finding);
        
        // Should still be valid after adding finding
        assert!(report.validate_integrity().unwrap());
    }
    
    #[test]
    fn test_json_serialization() {
        let investigator = create_test_investigator();
        let case_info = create_test_case();
        
        let report = ForensicReport::new(
            ReportType::LLMDetectionAnalysis,
            "Test Report".to_string(),
            investigator,
            case_info,
        );
        
        let json = report.to_json().unwrap();
        let deserialized = ForensicReport::from_json(&json).unwrap();
        
        assert_eq!(report.report_id, deserialized.report_id);
        assert_eq!(report.title, deserialized.title);
        assert_eq!(report.integrity_hash, deserialized.integrity_hash);
    }
}
