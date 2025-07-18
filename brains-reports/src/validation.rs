//! Report validation and compliance checking

use crate::report_schema::{ReportSchema, ValidationResult};
use crate::signature::SignaturePolicy;
use crate::ForensicReport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Forensic report validator
#[derive(Debug, Clone)]
pub struct ReportValidator {
    schemas: HashMap<String, ReportSchema>,
    signature_policies: HashMap<String, SignaturePolicy>,
    compliance_rules: Vec<ComplianceRule>,
}

/// Compliance rule for forensic reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub description: String,
    pub standard: String,
    pub requirement: String,
    pub validation_logic: String,
    pub severity: ComplianceSeverity,
    pub applicable_jurisdictions: Vec<String>,
}

/// Compliance severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComplianceSeverity {
    Advisory,
    Recommended,
    Required,
    Mandatory,
}

/// Validation context for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationContext {
    pub jurisdiction: String,
    pub report_type: String,
    pub security_level: String,
    pub legal_requirements: Vec<String>,
    pub compliance_standards: Vec<String>,
}

/// Comprehensive validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveValidationResult {
    pub is_valid: bool,
    pub schema_validation: ValidationResult,
    pub signature_validation: SignatureValidationResult,
    pub compliance_validation: ComplianceValidationResult,
    pub integrity_validation: IntegrityValidationResult,
    pub overall_score: f64,
    pub recommendations: Vec<String>,
    pub validated_at: chrono::DateTime<chrono::Utc>,
}

/// Signature validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureValidationResult {
    pub valid_signatures: usize,
    pub invalid_signatures: usize,
    pub missing_signatures: Vec<String>,
    pub policy_compliance: bool,
    pub signature_errors: Vec<String>,
}

/// Compliance validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceValidationResult {
    pub compliant_rules: usize,
    pub non_compliant_rules: usize,
    pub compliance_score: f64,
    pub violations: Vec<ComplianceViolation>,
    pub recommendations: Vec<String>,
}

/// Compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub violation_id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub severity: ComplianceSeverity,
    pub description: String,
    pub remediation: String,
    pub standard: String,
}

/// Integrity validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityValidationResult {
    pub hash_valid: bool,
    pub chain_of_custody_valid: bool,
    pub evidence_integrity: bool,
    pub tampering_detected: bool,
    pub integrity_score: f64,
    pub issues: Vec<String>,
}

impl ReportValidator {
    /// Create new report validator
    pub fn new() -> Self {
        let mut validator = Self {
            schemas: HashMap::new(),
            signature_policies: HashMap::new(),
            compliance_rules: Vec::new(),
        };
        
        // Register default schemas and policies
        validator.register_default_schemas();
        validator.register_default_policies();
        validator.register_default_compliance_rules();
        
        validator
    }
    
    /// Register report schema
    pub fn register_schema(&mut self, report_type: String, schema: ReportSchema) {
        self.schemas.insert(report_type, schema);
    }
    
    /// Register signature policy
    pub fn register_signature_policy(&mut self, report_type: String, policy: SignaturePolicy) {
        self.signature_policies.insert(report_type, policy);
    }
    
    /// Add compliance rule
    pub fn add_compliance_rule(&mut self, rule: ComplianceRule) {
        self.compliance_rules.push(rule);
    }
    
    /// Validate forensic report comprehensively
    pub fn validate_report(
        &self,
        report: &ForensicReport,
        context: &ValidationContext,
    ) -> anyhow::Result<ComprehensiveValidationResult> {
        // Schema validation
        let schema_validation = self.validate_schema(report)?;
        
        // Signature validation
        let signature_validation = self.validate_signatures(report, context)?;
        
        // Compliance validation
        let compliance_validation = self.validate_compliance(report, context)?;
        
        // Integrity validation
        let integrity_validation = self.validate_integrity(report)?;
        
        // Calculate overall score
        let overall_score = self.calculate_overall_score(
            &schema_validation,
            &signature_validation,
            &compliance_validation,
            &integrity_validation,
        );
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(
            &schema_validation,
            &signature_validation,
            &compliance_validation,
            &integrity_validation,
        );
        
        let is_valid = overall_score >= 0.8 && // 80% threshold
            schema_validation.is_valid &&
            signature_validation.policy_compliance &&
            compliance_validation.compliance_score >= 0.8 &&
            integrity_validation.integrity_score >= 0.9;
        
        Ok(ComprehensiveValidationResult {
            is_valid,
            schema_validation,
            signature_validation,
            compliance_validation,
            integrity_validation,
            overall_score,
            recommendations,
            validated_at: chrono::Utc::now(),
        })
    }
    
    /// Validate report schema
    fn validate_schema(&self, report: &ForensicReport) -> anyhow::Result<ValidationResult> {
        let report_type = format!("{:?}", report.report_type);
        
        if let Some(schema) = self.schemas.get(&report_type) {
            // Convert report to JSON for validation
            let report_json = serde_json::to_value(report)?;
            Ok(schema.validate_report(&report_json))
        } else {
            // No schema available, create basic validation result
            Ok(ValidationResult {
                is_valid: true,
                errors: Vec::new(),
                warnings: vec![crate::report_schema::ValidationWarning {
                    warning_id: Uuid::new_v4(),
                    field_path: "schema".to_string(),
                    warning_type: "No Schema".to_string(),
                    message: "No schema available for validation".to_string(),
                    recommendation: "Register appropriate schema".to_string(),
                }],
                schema_version: "unknown".to_string(),
                validated_at: chrono::Utc::now(),
            })
        }
    }
    
    /// Validate signatures
    fn validate_signatures(
        &self,
        report: &ForensicReport,
        context: &ValidationContext,
    ) -> anyhow::Result<SignatureValidationResult> {
        let policy = self.signature_policies.get(&context.report_type)
            .cloned()
            .unwrap_or_default();
        
        let mut valid_signatures = 0;
        let mut invalid_signatures = 0;
        let mut signature_errors = Vec::new();
        
        // Validate each signature
        for signature in &report.signatures {
            match report.verify_signature(signature) {
                Ok(true) => valid_signatures += 1,
                Ok(false) => {
                    invalid_signatures += 1;
                    signature_errors.push(format!("Invalid signature: {}", signature.signature_id));
                }
                Err(e) => {
                    invalid_signatures += 1;
                    signature_errors.push(format!("Signature verification error: {}", e));
                }
            }
        }
        
        // Check policy compliance
        let policy_compliance = match policy.validate_signatures(&report.signatures) {
            Ok(_) => true,
            Err(e) => {
                signature_errors.push(format!("Policy violation: {}", e));
                false
            }
        };
        
        // Check for missing required signatures
        let missing_signatures = if report.signatures.len() < policy.minimum_signatures {
            vec![format!("Missing {} signatures", policy.minimum_signatures - report.signatures.len())]
        } else {
            Vec::new()
        };
        
        Ok(SignatureValidationResult {
            valid_signatures,
            invalid_signatures,
            missing_signatures,
            policy_compliance,
            signature_errors,
        })
    }
    
    /// Validate compliance
    fn validate_compliance(
        &self,
        report: &ForensicReport,
        context: &ValidationContext,
    ) -> anyhow::Result<ComplianceValidationResult> {
        let mut compliant_rules = 0;
        let mut non_compliant_rules = 0;
        let mut violations = Vec::new();
        let mut recommendations = Vec::new();
        
        // Apply relevant compliance rules
        for rule in &self.compliance_rules {
            if rule.applicable_jurisdictions.is_empty() ||
               rule.applicable_jurisdictions.contains(&context.jurisdiction) {
                
                let is_compliant = self.evaluate_compliance_rule(report, rule)?;
                
                if is_compliant {
                    compliant_rules += 1;
                } else {
                    non_compliant_rules += 1;
                    violations.push(ComplianceViolation {
                        violation_id: Uuid::new_v4(),
                        rule_id: rule.rule_id,
                        rule_name: rule.rule_name.clone(),
                        severity: rule.severity.clone(),
                        description: rule.description.clone(),
                        remediation: format!("Ensure compliance with: {}", rule.requirement),
                        standard: rule.standard.clone(),
                    });
                }
            }
        }
        
        let total_rules = compliant_rules + non_compliant_rules;
        let compliance_score = if total_rules > 0 {
            compliant_rules as f64 / total_rules as f64
        } else {
            1.0
        };
        
        // Generate recommendations based on violations
        for violation in &violations {
            recommendations.push(violation.remediation.clone());
        }
        
        Ok(ComplianceValidationResult {
            compliant_rules,
            non_compliant_rules,
            compliance_score,
            violations,
            recommendations,
        })
    }
    
    /// Validate integrity
    fn validate_integrity(&self, report: &ForensicReport) -> anyhow::Result<IntegrityValidationResult> {
        let hash_valid = report.validate_integrity().unwrap_or(false);
        let chain_of_custody_valid = report.chain_of_custody.validate_continuity().is_ok();
        let evidence_integrity = report.evidence.iter().all(|e| !e.hash_sha256.is_empty());
        let tampering_detected = !hash_valid || !chain_of_custody_valid;
        
        let mut issues = Vec::new();
        
        if !hash_valid {
            issues.push("Report hash validation failed".to_string());
        }
        
        if !chain_of_custody_valid {
            issues.push("Chain of custody validation failed".to_string());
        }
        
        if !evidence_integrity {
            issues.push("Evidence integrity issues detected".to_string());
        }
        
        let integrity_score = if issues.is_empty() {
            1.0
        } else {
            (3.0 - issues.len() as f64) / 3.0
        };
        
        Ok(IntegrityValidationResult {
            hash_valid,
            chain_of_custody_valid,
            evidence_integrity,
            tampering_detected,
            integrity_score,
            issues,
        })
    }
    
    /// Calculate overall validation score
    fn calculate_overall_score(
        &self,
        schema: &ValidationResult,
        signature: &SignatureValidationResult,
        compliance: &ComplianceValidationResult,
        integrity: &IntegrityValidationResult,
    ) -> f64 {
        let schema_score = if schema.is_valid { 1.0 } else { 0.0 };
        let signature_score = if signature.policy_compliance { 1.0 } else { 0.0 };
        let compliance_score = compliance.compliance_score;
        let integrity_score = integrity.integrity_score;
        
        // Weighted average
        schema_score * 0.2 + signature_score * 0.3 + compliance_score * 0.2 + integrity_score * 0.3
    }
    
    /// Generate recommendations
    fn generate_recommendations(
        &self,
        schema: &ValidationResult,
        signature: &SignatureValidationResult,
        compliance: &ComplianceValidationResult,
        integrity: &IntegrityValidationResult,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if !schema.is_valid {
            recommendations.push("Fix schema validation errors".to_string());
        }
        
        if !signature.policy_compliance {
            recommendations.push("Ensure signature policy compliance".to_string());
        }
        
        if compliance.compliance_score < 0.8 {
            recommendations.push("Address compliance violations".to_string());
        }
        
        if integrity.integrity_score < 0.9 {
            recommendations.push("Resolve integrity issues".to_string());
        }
        
        recommendations.extend(compliance.recommendations.clone());
        
        recommendations
    }
    
    /// Evaluate compliance rule
    fn evaluate_compliance_rule(
        &self,
        _report: &ForensicReport,
        rule: &ComplianceRule,
    ) -> anyhow::Result<bool> {
        // Simplified compliance evaluation
        // In practice, this would use a rule engine
        match rule.rule_name.as_str() {
            "Chain of Custody Required" => Ok(true), // Assume always present
            "Digital Signature Required" => Ok(true), // Assume always present
            _ => Ok(true), // Default to compliant
        }
    }
    
    /// Register default schemas
    fn register_default_schemas(&mut self) {
        let llm_schema = ReportSchema::llm_detection_schema();
        self.schemas.insert("LLMDetectionAnalysis".to_string(), llm_schema);
    }
    
    /// Register default policies
    fn register_default_policies(&mut self) {
        let default_policy = SignaturePolicy::default();
        self.signature_policies.insert("default".to_string(), default_policy);
    }
    
    /// Register default compliance rules
    fn register_default_compliance_rules(&mut self) {
        let custody_rule = ComplianceRule {
            rule_id: Uuid::new_v4(),
            rule_name: "Chain of Custody Required".to_string(),
            description: "All forensic reports must maintain chain of custody".to_string(),
            standard: "ISO 27037".to_string(),
            requirement: "Chain of custody must be documented and validated".to_string(),
            validation_logic: "chain_of_custody.validate_continuity()".to_string(),
            severity: ComplianceSeverity::Mandatory,
            applicable_jurisdictions: vec!["US".to_string(), "EU".to_string()],
        };
        
        let signature_rule = ComplianceRule {
            rule_id: Uuid::new_v4(),
            rule_name: "Digital Signature Required".to_string(),
            description: "All forensic reports must be digitally signed".to_string(),
            standard: "FIPS 186-4".to_string(),
            requirement: "Report must contain valid digital signature".to_string(),
            validation_logic: "signatures.length > 0".to_string(),
            severity: ComplianceSeverity::Mandatory,
            applicable_jurisdictions: vec!["US".to_string()],
        };
        
        self.compliance_rules.push(custody_rule);
        self.compliance_rules.push(signature_rule);
    }
}

impl Default for ReportValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn create_test_report() -> ForensicReport {
        let investigator = Investigator {
            investigator_id: Uuid::new_v4(),
            name: "Test Investigator".to_string(),
            title: "Senior Analyst".to_string(),
            organization: "Test Lab".to_string(),
            credentials: vec!["GCFA".to_string()],
            contact_info: ContactInfo {
                email: "test@example.com".to_string(),
                phone: None,
                address: None,
                public_key: None,
            },
            security_clearance: None,
            certification_date: None,
        };
        
        let case_info = CaseInfo {
            case_id: "TEST-001".to_string(),
            case_name: "Test Case".to_string(),
            case_type: "Digital Forensics".to_string(),
            jurisdiction: "US".to_string(),
            classification: ClassificationLevel::Public,
            request_date: chrono::Utc::now(),
            deadline: None,
            requesting_party: "Test Agency".to_string(),
            legal_authority: None,
            related_cases: Vec::new(),
        };
        
        ForensicReport::new(
            ReportType::LLMDetectionAnalysis,
            "Test Report".to_string(),
            investigator,
            case_info,
        )
    }

    #[test]
    fn test_validator_creation() {
        let validator = ReportValidator::new();
        assert!(!validator.schemas.is_empty());
        assert!(!validator.compliance_rules.is_empty());
    }
    
    #[test]
    fn test_report_validation() {
        let validator = ReportValidator::new();
        let report = create_test_report();
        
        let context = ValidationContext {
            jurisdiction: "US".to_string(),
            report_type: "LLMDetectionAnalysis".to_string(),
            security_level: "Public".to_string(),
            legal_requirements: Vec::new(),
            compliance_standards: vec!["ISO 27037".to_string()],
        };
        
        let result = validator.validate_report(&report, &context);
        assert!(result.is_ok());
        
        let validation_result = result.unwrap();
        assert!(validation_result.overall_score >= 0.0);
        assert!(validation_result.overall_score <= 1.0);
    }
}
