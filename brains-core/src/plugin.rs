//! Plugin interface definitions and metadata structures

use crate::versioning::ApiVersion;
use brains_detection::PatternEngine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

/// Plugin interface for forensic analysis engines
pub trait PluginInterface {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;
    
    /// Build pattern engine for analysis
    fn build_engine(&self) -> anyhow::Result<Arc<dyn PatternEngine + Send + Sync>>;
    
    /// Initialize plugin with configuration
    fn initialize(&mut self, config: &PluginConfig) -> anyhow::Result<()>;
    
    /// Execute plugin analysis
    fn analyze(&self, input: &PluginInput) -> anyhow::Result<PluginOutput>;
    
    /// Cleanup plugin resources
    fn cleanup(&mut self) -> anyhow::Result<()>;
    
    /// Get plugin health status
    fn health_check(&self) -> PluginHealth;
}

/// Plugin metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub api_version: ApiVersion,
    pub description: String,
    pub author: String,
    pub license: String,
    pub categories: Vec<PluginCategory>,
    pub capabilities: Vec<String>,
    pub dependencies: Vec<PluginDependency>,
    pub configuration_schema: Option<String>,
    pub security_requirements: SecurityRequirements,
    pub resource_requirements: ResourceRequirements,
    pub validation_info: ValidationInfo,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Plugin categories for classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCategory {
    PatternDetection,
    LLMAnalysis,
    SurveillanceDetection,
    MalwareAnalysis,
    ForensicUtility,
    Correlation,
    Reporting,
    Experimental,
}

/// Plugin dependency specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    pub name: String,
    pub version_requirement: String,
    pub optional: bool,
    pub description: String,
}

/// Security requirements for plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequirements {
    pub minimum_security_level: SecurityLevel,
    pub requires_signature: bool,
    pub requires_sandboxing: bool,
    pub network_access: bool,
    pub file_system_access: bool,
    pub system_calls: bool,
    pub sensitive_data_access: bool,
}

/// Security levels for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Public,
    Restricted,
    Classified,
}

/// Resource requirements for plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub max_memory_mb: usize,
    pub max_cpu_time_seconds: u64,
    pub max_disk_space_mb: usize,
    pub max_network_connections: usize,
    pub requires_gpu: bool,
    pub supports_parallel_execution: bool,
}

/// Validation information for plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationInfo {
    pub validation_status: ValidationStatus,
    pub test_results: Vec<TestResult>,
    pub performance_benchmarks: Vec<PerformanceBenchmark>,
    pub security_audit: Option<SecurityAudit>,
    pub false_positive_rate: Option<f64>,
    pub false_negative_rate: Option<f64>,
    pub last_validated: chrono::DateTime<chrono::Utc>,
}

/// Validation status for plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Unvalidated,
    InProgress,
    Validated,
    Failed,
    Deprecated,
}

/// Test result for plugin validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_name: String,
    pub test_type: TestType,
    pub status: TestStatus,
    pub duration_ms: u64,
    pub details: String,
    pub error_message: Option<String>,
}

/// Test types for plugin validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestType {
    Unit,
    Integration,
    Performance,
    Security,
    Compatibility,
}

/// Test status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Error,
}

/// Performance benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBenchmark {
    pub benchmark_name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub unit: String,
    pub baseline_value: Option<f64>,
    pub improvement_percentage: Option<f64>,
}

/// Performance metric types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Throughput,
    Latency,
    Accuracy,
    Precision,
    Recall,
    F1Score,
    MemoryUsage,
    CpuUsage,
}

/// Security audit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAudit {
    pub audit_id: Uuid,
    pub auditor: String,
    pub audit_date: chrono::DateTime<chrono::Utc>,
    pub findings: Vec<SecurityFinding>,
    pub risk_level: RiskLevel,
    pub recommendations: Vec<String>,
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub finding_id: Uuid,
    pub severity: SecuritySeverity,
    pub category: String,
    pub description: String,
    pub remediation: String,
    pub status: FindingStatus,
}

/// Security severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Finding status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    InProgress,
    Resolved,
    Accepted,
    Deferred,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub plugin_name: String,
    pub config_version: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub security_context: SecurityContext,
    pub resource_limits: ResourceLimits,
    pub execution_environment: ExecutionEnvironment,
}

/// Security context for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub security_level: SecurityLevel,
    pub allowed_operations: Vec<String>,
    pub sandbox_enabled: bool,
    pub audit_enabled: bool,
    pub encryption_required: bool,
}

/// Resource limits for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_time_seconds: u64,
    pub max_disk_io_mb: usize,
    pub max_network_requests: usize,
    pub max_file_descriptors: usize,
}

/// Execution environment for plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEnvironment {
    pub working_directory: PathBuf,
    pub temp_directory: PathBuf,
    pub environment_variables: HashMap<String, String>,
    pub allowed_file_paths: Vec<PathBuf>,
    pub blocked_file_paths: Vec<PathBuf>,
}

/// Plugin input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInput {
    pub input_id: Uuid,
    pub input_type: InputType,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub options: HashMap<String, serde_json::Value>,
}

/// Input types for plugin analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputType {
    SourceCode,
    Binary,
    NetworkCapture,
    LogFile,
    Artifact,
    Custom(String),
}

/// Plugin output data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    pub output_id: Uuid,
    pub results: Vec<AnalysisResult>,
    pub metadata: HashMap<String, String>,
    pub performance_metrics: PluginPerformanceMetrics,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Analysis result from plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub result_id: Uuid,
    pub result_type: String,
    pub confidence: f64,
    pub data: serde_json::Value,
    pub evidence: Vec<Evidence>,
    pub metadata: HashMap<String, String>,
}

/// Evidence supporting analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: Uuid,
    pub evidence_type: String,
    pub description: String,
    pub location: Option<Location>,
    pub confidence: f64,
    pub data: serde_json::Value,
}

/// Location information for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file_path: Option<String>,
    pub line_start: Option<usize>,
    pub line_end: Option<usize>,
    pub column_start: Option<usize>,
    pub column_end: Option<usize>,
    pub byte_offset: Option<usize>,
    pub byte_length: Option<usize>,
}

/// Performance metrics for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPerformanceMetrics {
    pub execution_time_ms: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub disk_io_mb: f64,
    pub network_requests: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
}

/// Plugin health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginHealth {
    pub status: HealthStatus,
    pub message: String,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub performance_metrics: PluginPerformanceMetrics,
    pub error_count: usize,
    pub warning_count: usize,
}

/// Health status levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
    Unknown,
}

/// Plugin instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    pub metadata: PluginMetadata,
    pub library_path: PathBuf,
    pub loaded: bool,
}

impl PluginInterface for Plugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    fn build_engine(&self) -> anyhow::Result<Arc<dyn PatternEngine + Send + Sync>> {
        let engine = brains_detection::BasicLLMDetector::new();
        Ok(Arc::new(engine))
    }
    
    fn initialize(&mut self, _config: &PluginConfig) -> anyhow::Result<()> {
        self.loaded = true;
        Ok(())
    }
    
    fn analyze(&self, _input: &PluginInput) -> anyhow::Result<PluginOutput> {
        Err(anyhow::anyhow!("Use build_engine() to get PatternEngine for analysis"))
    }
    
    fn cleanup(&mut self) -> anyhow::Result<()> {
        self.loaded = false;
        Ok(())
    }
    
    fn health_check(&self) -> PluginHealth {
        PluginHealth {
            status: if self.loaded { HealthStatus::Healthy } else { HealthStatus::Unknown },
            message: "Plugin status".to_string(),
            last_check: chrono::Utc::now(),
            performance_metrics: PluginPerformanceMetrics {
                execution_time_ms: 0,
                memory_usage_mb: 0.0,
                cpu_usage_percent: 0.0,
                disk_io_mb: 0.0,
                network_requests: 0,
                cache_hits: 0,
                cache_misses: 0,
            },
            error_count: 0,
            warning_count: 0,
        }
    }
}

impl PluginMetadata {
    /// Create default metadata for plugin name
    pub fn default_for_name(name: String) -> Self {
        let now = chrono::Utc::now();
        
        Self {
            name,
            version: "0.1.0".to_string(),
            api_version: ApiVersion::current(),
            description: "No description provided".to_string(),
            author: "Unknown".to_string(),
            license: "Unknown".to_string(),
            categories: vec![PluginCategory::Experimental],
            capabilities: Vec::new(),
            dependencies: Vec::new(),
            configuration_schema: None,
            security_requirements: SecurityRequirements {
                minimum_security_level: SecurityLevel::Public,
                requires_signature: false,
                requires_sandboxing: false,
                network_access: false,
                file_system_access: false,
                system_calls: false,
                sensitive_data_access: false,
            },
            resource_requirements: ResourceRequirements {
                max_memory_mb: 256,
                max_cpu_time_seconds: 60,
                max_disk_space_mb: 100,
                max_network_connections: 0,
                requires_gpu: false,
                supports_parallel_execution: false,
            },
            validation_info: ValidationInfo {
                validation_status: ValidationStatus::Unvalidated,
                test_results: Vec::new(),
                performance_benchmarks: Vec::new(),
                security_audit: None,
                false_positive_rate: None,
                false_negative_rate: None,
                last_validated: now,
            },
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_metadata_creation() {
        let metadata = PluginMetadata::default_for_name("test_plugin".to_string());
        
        assert_eq!(metadata.name, "test_plugin");
        assert_eq!(metadata.version, "0.1.0");
        assert_eq!(metadata.categories, vec![PluginCategory::Experimental]);
        assert_eq!(metadata.security_requirements.minimum_security_level, SecurityLevel::Public);
    }
    
    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Public < SecurityLevel::Restricted);
        assert!(SecurityLevel::Restricted < SecurityLevel::Classified);
    }
    
    #[test]
    fn test_security_severity_ordering() {
        assert!(SecuritySeverity::Info < SecuritySeverity::Low);
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
        assert!(SecuritySeverity::High < SecuritySeverity::Critical);
    }
    
    #[test]
    fn test_plugin_serialization() {
        let metadata = PluginMetadata::default_for_name("test_plugin".to_string());
        
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: PluginMetadata = serde_json::from_str(&json).unwrap();
        
        assert_eq!(metadata.name, deserialized.name);
        assert_eq!(metadata.version, deserialized.version);
    }
}