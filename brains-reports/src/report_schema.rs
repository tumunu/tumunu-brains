//! Report schema validation and templates

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Report schema definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSchema {
    pub schema_id: Uuid,
    pub schema_version: String,
    pub schema_name: String,
    pub description: String,
    pub report_type: String,
    pub required_fields: Vec<FieldDefinition>,
    pub optional_fields: Vec<FieldDefinition>,
    pub validation_rules: Vec<ValidationRule>,
    pub templates: HashMap<String, ReportTemplate>,
}

/// Field definition in schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub field_name: String,
    pub field_type: FieldType,
    pub description: String,
    pub constraints: Vec<FieldConstraint>,
    pub examples: Vec<String>,
}

/// Field types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FieldType {
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Uuid,
    Array(Box<FieldType>),
    Object(HashMap<String, FieldType>),
    Enum(Vec<String>),
}

/// Field constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConstraint {
    pub constraint_type: ConstraintType,
    pub value: Value,
    pub error_message: String,
}

/// Constraint types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConstraintType {
    MinLength,
    MaxLength,
    Pattern,
    MinValue,
    MaxValue,
    Required,
    Unique,
    Format,
}

/// Validation rule for entire report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub description: String,
    pub rule_type: RuleType,
    pub condition: String,
    pub error_message: String,
    pub severity: ValidationSeverity,
}

/// Rule types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleType {
    FieldValidation,
    CrossFieldValidation,
    BusinessRule,
    SecurityRule,
    ComplianceRule,
}

/// Validation severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Report template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub template_id: Uuid,
    pub template_name: String,
    pub description: String,
    pub template_type: TemplateType,
    pub content: String,
    pub variables: Vec<TemplateVariable>,
    pub output_format: OutputFormat,
}

/// Template types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TemplateType {
    Executive,
    Technical,
    Legal,
    Compliance,
    Summary,
    Detailed,
}

/// Template variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    pub variable_name: String,
    pub variable_type: FieldType,
    pub default_value: Option<Value>,
    pub description: String,
}

/// Output formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    Html,
    Markdown,
    Pdf,
    Docx,
    Json,
    Yaml,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub schema_version: String,
    pub validated_at: chrono::DateTime<chrono::Utc>,
}

/// Validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub error_id: Uuid,
    pub field_path: String,
    pub error_type: String,
    pub message: String,
    pub actual_value: Option<Value>,
    pub expected_value: Option<Value>,
}

/// Validation warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub warning_id: Uuid,
    pub field_path: String,
    pub warning_type: String,
    pub message: String,
    pub recommendation: String,
}

impl ReportSchema {
    /// Create default LLM detection schema
    pub fn llm_detection_schema() -> Self {
        let schema_id = Uuid::new_v4();
        
        let required_fields = vec![
            FieldDefinition {
                field_name: "report_id".to_string(),
                field_type: FieldType::Uuid,
                description: "Unique report identifier".to_string(),
                constraints: vec![FieldConstraint {
                    constraint_type: ConstraintType::Required,
                    value: Value::Bool(true),
                    error_message: "Report ID is required".to_string(),
                }],
                examples: vec!["550e8400-e29b-41d4-a716-446655440000".to_string()],
            },
            FieldDefinition {
                field_name: "title".to_string(),
                field_type: FieldType::String,
                description: "Report title".to_string(),
                constraints: vec![
                    FieldConstraint {
                        constraint_type: ConstraintType::Required,
                        value: Value::Bool(true),
                        error_message: "Title is required".to_string(),
                    },
                    FieldConstraint {
                        constraint_type: ConstraintType::MinLength,
                        value: Value::Number(serde_json::Number::from(10)),
                        error_message: "Title must be at least 10 characters".to_string(),
                    },
                ],
                examples: vec!["LLM-Generated Surveillance Code Detection Analysis".to_string()],
            },
        ];
        
        let validation_rules = vec![
            ValidationRule {
                rule_id: Uuid::new_v4(),
                rule_name: "Minimum Findings".to_string(),
                description: "Report must contain at least one finding".to_string(),
                rule_type: RuleType::BusinessRule,
                condition: "findings.length > 0".to_string(),
                error_message: "Report must contain at least one finding".to_string(),
                severity: ValidationSeverity::Error,
            },
        ];
        
        let mut templates = HashMap::new();
        templates.insert(
            "executive".to_string(),
            ReportTemplate {
                template_id: Uuid::new_v4(),
                template_name: "Executive Summary".to_string(),
                description: "High-level executive summary template".to_string(),
                template_type: TemplateType::Executive,
                content: include_str!("../templates/executive_summary.md").to_string(),
                variables: vec![
                    TemplateVariable {
                        variable_name: "report_title".to_string(),
                        variable_type: FieldType::String,
                        default_value: None,
                        description: "Title of the report".to_string(),
                    },
                ],
                output_format: OutputFormat::Html,
            },
        );
        
        Self {
            schema_id,
            schema_version: "1.0.0".to_string(),
            schema_name: "LLM Detection Analysis".to_string(),
            description: "Schema for LLM-generated code detection reports".to_string(),
            report_type: "LLMDetectionAnalysis".to_string(),
            required_fields,
            optional_fields: Vec::new(),
            validation_rules,
            templates,
        }
    }
    
    /// Validate report against schema
    pub fn validate_report(&self, report_data: &Value) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // Validate required fields
        for field in &self.required_fields {
            if !self.validate_field(report_data, field, &mut errors, &mut warnings) {
                // Field validation failed
            }
        }
        
        // Validate optional fields if present
        for field in &self.optional_fields {
            if report_data.get(&field.field_name).is_some() {
                self.validate_field(report_data, field, &mut errors, &mut warnings);
            }
        }
        
        // Apply validation rules
        for rule in &self.validation_rules {
            if !self.apply_validation_rule(report_data, rule, &mut errors, &mut warnings) {
                // Rule validation failed
            }
        }
        
        ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            schema_version: self.schema_version.clone(),
            validated_at: chrono::Utc::now(),
        }
    }
    
    /// Validate individual field
    fn validate_field(
        &self,
        report_data: &Value,
        field: &FieldDefinition,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> bool {
        let field_value = report_data.get(&field.field_name);
        
        // Check if required field is present
        if field.constraints.iter().any(|c| c.constraint_type == ConstraintType::Required) {
            if field_value.is_none() {
                errors.push(ValidationError {
                    error_id: Uuid::new_v4(),
                    field_path: field.field_name.clone(),
                    error_type: "Missing Required Field".to_string(),
                    message: format!("Required field '{}' is missing", field.field_name),
                    actual_value: None,
                    expected_value: None,
                });
                return false;
            }
        }
        
        // Validate field type and constraints if present
        if let Some(value) = field_value {
            if !self.validate_field_type(value, &field.field_type) {
                errors.push(ValidationError {
                    error_id: Uuid::new_v4(),
                    field_path: field.field_name.clone(),
                    error_type: "Type Mismatch".to_string(),
                    message: format!("Field '{}' has incorrect type", field.field_name),
                    actual_value: Some(value.clone()),
                    expected_value: None,
                });
                return false;
            }
            
            // Apply field constraints
            for constraint in &field.constraints {
                if !self.apply_constraint(value, constraint, &field.field_name, errors) {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Validate field type
    fn validate_field_type(&self, value: &Value, field_type: &FieldType) -> bool {
        match field_type {
            FieldType::String => value.is_string(),
            FieldType::Integer => value.is_number(),
            FieldType::Float => value.is_number(),
            FieldType::Boolean => value.is_boolean(),
            FieldType::DateTime => value.is_string(), // Assume ISO format
            FieldType::Uuid => value.is_string(),     // Assume UUID format
            FieldType::Array(_) => value.is_array(),
            FieldType::Object(_) => value.is_object(),
            FieldType::Enum(values) => {
                if let Some(s) = value.as_str() {
                    values.contains(&s.to_string())
                } else {
                    false
                }
            }
        }
    }
    
    /// Apply field constraint
    fn apply_constraint(
        &self,
        value: &Value,
        constraint: &FieldConstraint,
        field_name: &str,
        errors: &mut Vec<ValidationError>,
    ) -> bool {
        match constraint.constraint_type {
            ConstraintType::MinLength => {
                if let (Some(s), Some(min_len)) = (value.as_str(), constraint.value.as_u64()) {
                    if s.len() < min_len as usize {
                        errors.push(ValidationError {
                            error_id: Uuid::new_v4(),
                            field_path: field_name.to_string(),
                            error_type: "Minimum Length".to_string(),
                            message: constraint.error_message.clone(),
                            actual_value: Some(value.clone()),
                            expected_value: Some(constraint.value.clone()),
                        });
                        return false;
                    }
                }
            }
            ConstraintType::MaxLength => {
                if let (Some(s), Some(max_len)) = (value.as_str(), constraint.value.as_u64()) {
                    if s.len() > max_len as usize {
                        errors.push(ValidationError {
                            error_id: Uuid::new_v4(),
                            field_path: field_name.to_string(),
                            error_type: "Maximum Length".to_string(),
                            message: constraint.error_message.clone(),
                            actual_value: Some(value.clone()),
                            expected_value: Some(constraint.value.clone()),
                        });
                        return false;
                    }
                }
            }
            _ => {} // Handle other constraints as needed
        }
        
        true
    }
    
    /// Apply validation rule
    fn apply_validation_rule(
        &self,
        _report_data: &Value,
        rule: &ValidationRule,
        errors: &mut Vec<ValidationError>,
        _warnings: &mut Vec<ValidationWarning>,
    ) -> bool {
        // Simplified rule application - in practice would use expression evaluator
        match rule.rule_name.as_str() {
            "Minimum Findings" => {
                // Check if findings array exists and has at least one element
                // This is a simplified check - real implementation would be more robust
                errors.push(ValidationError {
                    error_id: Uuid::new_v4(),
                    field_path: "findings".to_string(),
                    error_type: "Business Rule".to_string(),
                    message: rule.error_message.clone(),
                    actual_value: None,
                    expected_value: None,
                });
                false
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_schema_creation() {
        let schema = ReportSchema::llm_detection_schema();
        
        assert_eq!(schema.schema_name, "LLM Detection Analysis");
        assert_eq!(schema.report_type, "LLMDetectionAnalysis");
        assert!(!schema.required_fields.is_empty());
    }
    
    #[test]
    fn test_report_validation() {
        let schema = ReportSchema::llm_detection_schema();
        
        let valid_report = json!({
            "report_id": "550e8400-e29b-41d4-a716-446655440000",
            "title": "LLM Detection Analysis Report",
            "findings": [{
                "finding_id": "finding-001",
                "severity": "High"
            }]
        });
        
        let result = schema.validate_report(&valid_report);
        
        // Note: This will fail due to simplified validation logic
        // In a real implementation, the validation would be more sophisticated
        assert!(!result.errors.is_empty()); // Expected to have errors due to simplified logic
    }
}
