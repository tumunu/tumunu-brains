//! # Brains Core
//! 
//! Core plugin system and APIs for forensic intelligence platform.
//! Provides versioned interfaces for extensible detection and analysis engines.

use brains_detection::{DetectionResult, PatternEngine, EngineCapabilities};
use brains_ontology::{DetectionOntology, PerformanceMetrics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

pub mod registry;
pub mod plugin;
pub mod versioning;
pub mod governance;
pub mod fs_scanner;
pub mod system_metrics;
pub mod orchestrator;

pub use registry::PluginRegistry;
pub use plugin::{Plugin, PluginMetadata, PluginInterface};
pub use versioning::{ApiVersion, Compatibility};
pub use governance::{PluginGovernance, ApprovalStatus};
pub use fs_scanner::{ScanOptions, SourceFile, collect_source_files, default_ext_map, parse_ext_map_config, merge_ext_maps};
pub use system_metrics::{SystemMetrics, MetricsProvider, SysinfoMetricsProvider};
pub use orchestrator::{EngineOrchestrator, ExecError};

/// Core plugin system for forensic intelligence platform
#[derive(Serialize, Deserialize)]
pub struct ForensicCore {
    pub version: ApiVersion,
    pub plugin_registry: PluginRegistry,
    pub governance: PluginGovernance,
    #[serde(skip)]
    pub active_engines: HashMap<String, Box<dyn PatternEngine>>,
    pub configuration: CoreConfiguration,
    #[serde(skip)]
    pub metrics_provider: Option<SysinfoMetricsProvider>,
    #[serde(skip)]
    pub orchestrator: Option<EngineOrchestrator>,
}

impl Clone for ForensicCore {
    fn clone(&self) -> Self {
        Self {
            version: self.version.clone(),
            plugin_registry: self.plugin_registry.clone(),
            governance: self.governance.clone(),
            active_engines: HashMap::new(),
            configuration: self.configuration.clone(),
            metrics_provider: None,
            orchestrator: None,
        }
    }
}

impl std::fmt::Debug for ForensicCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForensicCore")
            .field("version", &self.version)
            .field("plugin_registry", &self.plugin_registry)
            .field("governance", &self.governance)
            .field("active_engines", &format!("{} engines", self.active_engines.len()))
            .field("configuration", &self.configuration)
            .field("metrics_provider", &self.metrics_provider.is_some())
            .field("orchestrator", &self.orchestrator.is_some())
            .finish()
    }
}

/// Core system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfiguration {
    pub plugin_directory: PathBuf,
    pub enable_experimental_plugins: bool,
    pub require_plugin_signatures: bool,
    pub max_concurrent_analyses: usize,
    pub analysis_timeout_seconds: u64,
    pub cache_size_mb: usize,
    pub logging_level: String,
}

/// Plugin execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub context_id: Uuid,
    pub session_id: Uuid,
    pub investigator_id: String,
    pub case_id: String,
    pub security_level: SecurityLevel,
    pub resource_limits: ResourceLimits,
    pub environment: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Security levels for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Public,
    Restricted,
    Classified,
}

/// Resource limits for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_time_seconds: u64,
    pub max_disk_io_mb: usize,
    pub max_network_requests: usize,
    pub allow_file_system_access: bool,
    pub allow_network_access: bool,
}

/// Analysis request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub request_id: Uuid,
    pub input_data: AnalysisInput,
    pub requested_engines: Vec<String>,
    pub analysis_options: AnalysisOptions,
    pub context: ExecutionContext,
    pub priority: RequestPriority,
}

/// Analysis input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisInput {
    SourceCode {
        content: String,
        language: String,
        file_path: Option<String>,
    },
    BinaryData {
        data: Vec<u8>,
        format: String,
        metadata: HashMap<String, String>,
    },
    NetworkCapture {
        pcap_data: Vec<u8>,
        metadata: HashMap<String, String>,
    },
    LogEntries {
        entries: Vec<String>,
        log_type: String,
        metadata: HashMap<String, String>,
    },
    Artifacts {
        artifacts: Vec<ForensicArtifact>,
        metadata: HashMap<String, String>,
    },
}

/// Forensic artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicArtifact {
    pub artifact_id: Uuid,
    pub artifact_type: String,
    pub content: Vec<u8>,
    pub hash: String,
    pub metadata: HashMap<String, String>,
    pub chain_of_custody: Vec<CustodyEntry>,
}

/// Chain of custody entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub entry_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub handler: String,
    pub action: String,
    pub description: String,
    pub signature: Option<String>,
}

/// Analysis options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    pub confidence_threshold: f64,
    pub enable_deep_analysis: bool,
    pub enable_correlation: bool,
    pub enable_provenance_tracking: bool,
    pub output_format: OutputFormat,
    pub include_raw_data: bool,
    pub anonymize_results: bool,
}

/// Output format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Xml,
    Yaml,
    Markdown,
    Pdf,
    Custom(String),
}

/// Request priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestPriority {
    Low,
    Normal,
    High,
    Critical,
    Emergency,
}

/// Analysis response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub response_id: Uuid,
    pub request_id: Uuid,
    pub results: Vec<DetectionResult>,
    pub performance_metrics: AnalysisMetrics,
    pub execution_metadata: ExecutionMetadata,
    pub status: AnalysisStatus,
    pub errors: Vec<AnalysisError>,
    pub warnings: Vec<String>,
}

/// Analysis metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    pub total_execution_time_ms: u64,
    pub engine_execution_times: HashMap<String, u64>,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub disk_io_mb: f64,
    pub network_requests: usize,
    pub cache_hit_rate: f64,
}

/// Execution metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetadata {
    pub platform: String,
    pub architecture: String,
    pub rust_version: String,
    pub brains_version: String,
    pub plugin_versions: HashMap<String, String>,
    pub environment_hash: String,
    pub execution_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Analysis status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Timeout,
}

/// Analysis error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisError {
    pub error_id: Uuid,
    pub error_type: String,
    pub message: String,
    pub engine: Option<String>,
    pub severity: ErrorSeverity,
    pub recoverable: bool,
    pub context: HashMap<String, String>,
}

/// Error severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Fatal,
}

/// Engine orchestration system
pub struct EngineOrchestrator {
    engines: HashMap<String, Box<dyn PatternEngine>>,
    execution_queue: Vec<AnalysisRequest>,
    running_analyses: HashMap<Uuid, AnalysisTask>,
    configuration: CoreConfiguration,
}

/// Analysis task
#[derive(Debug)]
pub struct AnalysisTask {
    pub task_id: Uuid,
    pub request: AnalysisRequest,
    pub status: AnalysisStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub estimated_completion: Option<chrono::DateTime<chrono::Utc>>,
    pub progress: f64,
}

impl ForensicCore {
    /// Create new forensic core system
    pub fn new(configuration: CoreConfiguration) -> anyhow::Result<Self> {
        let version = ApiVersion::current();
        let plugin_registry = PluginRegistry::new(configuration.plugin_directory.clone())?;
        let governance = PluginGovernance::new();
        
        Ok(Self {
            version,
            plugin_registry,
            governance,
            active_engines: HashMap::new(),
            configuration,
            metrics_provider: Some(SysinfoMetricsProvider::new()),
            orchestrator: Some(EngineOrchestrator::new(
                configuration.max_concurrent_analyses,
                std::time::Duration::from_secs(configuration.analysis_timeout_seconds)
            )),
        })
    }
    
    pub fn load_plugin(&mut self, plugin_path: PathBuf) -> anyhow::Result<()> {
        let plugin = self.plugin_registry.load_plugin(plugin_path)?;
        
        if !self.governance.is_approved(&plugin.metadata.name) {
            return Err(anyhow::anyhow!("Plugin not approved by governance: {}", plugin.metadata.name));
        }
        
        if !self.version.is_compatible(&plugin.metadata.api_version) {
            return Err(anyhow::anyhow!("Plugin API version incompatible: {} requires {}", 
                plugin.metadata.name, plugin.metadata.api_version));
        }
        
        let engine = plugin.build_engine()?;
        self.plugin_registry.register_engine(engine)?;
        self.plugin_registry.register_plugin(plugin)?;
        
        Ok(())
    }
    
    pub async fn execute_analysis(&mut self, request: AnalysisRequest) -> anyhow::Result<AnalysisResponse> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut engine_times = HashMap::new();
        
        self.validate_request(&request)?;
        
        let orchestrator = self.orchestrator.clone()
            .ok_or_else(|| anyhow::anyhow!("Orchestrator not initialized"))?;
        
        for engine_name in &request.requested_engines {
            let engine_start = std::time::Instant::now();
            
            if let Some(engine) = self.plugin_registry.get_engine(engine_name) {
                match orchestrator.execute(engine, request.input_data.clone()).await {
                    Ok(mut engine_results) => {
                        results.append(&mut engine_results);
                    }
                    Err(e) => {
                        errors.push(AnalysisError {
                            error_id: Uuid::new_v4(),
                            error_type: "engine_execution".to_string(),
                            message: e.to_string(),
                            engine: Some(engine_name.clone()),
                            severity: ErrorSeverity::Error,
                            recoverable: true,
                            context: HashMap::new(),
                        });
                    }
                }
            } else {
                errors.push(AnalysisError {
                    error_id: Uuid::new_v4(),
                    error_type: "engine_not_found".to_string(),
                    message: format!("Engine not found: {}", engine_name),
                    engine: Some(engine_name.clone()),
                    severity: ErrorSeverity::Error,
                    recoverable: false,
                    context: HashMap::new(),
                });
            }
            
            engine_times.insert(engine_name.clone(), engine_start.elapsed().as_millis() as u64);
        }
        
        let total_time = start_time.elapsed().as_millis() as u64;
        
        // Build response
        let response = AnalysisResponse {
            response_id: Uuid::new_v4(),
            request_id: request.request_id,
            results,
            performance_metrics: AnalysisMetrics {
                total_execution_time_ms: total_time,
                engine_execution_times: engine_times,
                memory_usage_mb: if let Some(ref mut provider) = self.metrics_provider {
                    let metrics = provider.sample();
                    (metrics.mem_used as f64) / (1024.0 * 1024.0)
                } else { 0.0 },
                cpu_usage_percent: if let Some(ref mut provider) = self.metrics_provider {
                    let metrics = provider.sample();
                    metrics.cpu_usage as f64
                } else { 0.0 },
                disk_io_mb: if let Some(ref mut provider) = self.metrics_provider {
                    let metrics = provider.sample();
                    (metrics.disk_read_bytes + metrics.disk_written_bytes) as f64 / (1024.0 * 1024.0)
                } else { 0.0 },
                network_requests: 0,
                cache_hit_rate: 0.0,
            },
            execution_metadata: ExecutionMetadata {
                platform: std::env::consts::OS.to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                rust_version: option_env!("RUSTC_VERSION").unwrap_or("unknown").to_string(),
                brains_version: env!("CARGO_PKG_VERSION").to_string(),
                plugin_versions: self.collect_plugin_versions(),
                environment_hash: Self::generate_environment_hash(),
                execution_timestamp: chrono::Utc::now(),
            },
            status: if errors.is_empty() { AnalysisStatus::Completed } else { AnalysisStatus::Failed },
            errors,
            warnings,
        };
        
        Ok(response)
    }
    
    /// Validate analysis request
    fn validate_request(&self, request: &AnalysisRequest) -> anyhow::Result<()> {
        // Check security level
        match request.context.security_level {
            SecurityLevel::Classified => {
                if !self.configuration.require_plugin_signatures {
                    return Err(anyhow::anyhow!("Classified analysis requires plugin signatures"));
                }
            }
            _ => {}
        }
        
        // Check resource limits
        if request.context.resource_limits.max_memory_mb > 8192 {
            return Err(anyhow::anyhow!("Memory limit too high: {}", request.context.resource_limits.max_memory_mb));
        }
        
        for engine_name in &request.requested_engines {
            if self.plugin_registry.get_engine(engine_name).is_none() {
                return Err(anyhow::anyhow!("Engine not found: {}", engine_name));
            }
        }
        
        Ok(())
    }
    
    
    /// Get system status
    pub fn get_system_status(&self) -> SystemStatus {
        SystemStatus {
            version: self.version.clone(),
            loaded_plugins: self.plugin_registry.list_plugins().len(),
            active_engines: self.plugin_registry.list_engines().len(),
            running_analyses: self.get_running_analyses_count(),
            system_health: SystemHealth::Healthy,
            resource_usage: ResourceUsage {
                memory_usage_mb: if let Some(ref mut provider) = self.metrics_provider {
                    let metrics = provider.sample();
                    (metrics.mem_used as f64) / (1024.0 * 1024.0)
                } else { 0.0 },
                cpu_usage_percent: if let Some(ref mut provider) = self.metrics_provider {
                    let metrics = provider.sample();
                    metrics.cpu_usage as f64
                } else { 0.0 },
                disk_usage_mb: if let Some(ref mut provider) = self.metrics_provider {
                    let metrics = provider.sample();
                    (metrics.disk_usage_pct as f64 * metrics.mem_total as f64) / (100.0 * 1024.0 * 1024.0)
                } else { 0.0 },
                network_connections: 0,
            },
        }
    }
    
    
    /// Collect plugin versions
    fn collect_plugin_versions(&self) -> HashMap<String, String> {
        let mut versions = HashMap::new();
        
        for plugin in self.plugin_registry.list_plugins() {
            versions.insert(plugin.name.clone(), plugin.version.clone());
        }
        
        // Add core component versions
        versions.insert("brains-core".to_string(), env!("CARGO_PKG_VERSION").to_string());
        versions.insert("brains-detection".to_string(), env!("CARGO_PKG_VERSION").to_string());
        versions.insert("brains-forensics".to_string(), env!("CARGO_PKG_VERSION").to_string());
        
        versions
    }
    
    /// Generate environment hash for reproducibility
    fn generate_environment_hash() -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        
        // Hash environment variables that affect analysis
        std::env::consts::OS.hash(&mut hasher);
        std::env::consts::ARCH.hash(&mut hasher);
        env!("CARGO_PKG_VERSION").hash(&mut hasher);
        
        // Hash current working directory
        if let Ok(cwd) = std::env::current_dir() {
            cwd.to_string_lossy().hash(&mut hasher);
        }
        
        // Hash relevant environment variables
        for var in ["PATH", "RUST_VERSION", "CARGO_HOME"].iter() {
            if let Ok(value) = std::env::var(var) {
                var.hash(&mut hasher);
                value.hash(&mut hasher);
            }
        }
        
        format!("{:x}", hasher.finish())
    }
    
    /// Get count of running analyses
    fn get_running_analyses_count(&self) -> usize {
        // In a real implementation, this would track active analysis tasks
        // For now, return 0 as no analyses are tracked in this struct
        0
    }
}

/// System status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub version: ApiVersion,
    pub loaded_plugins: usize,
    pub active_engines: usize,
    pub running_analyses: usize,
    pub system_health: SystemHealth,
    pub resource_usage: ResourceUsage,
}

/// System health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
}

/// Resource usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub disk_usage_mb: f64,
    pub network_connections: usize,
}

impl Default for CoreConfiguration {
    fn default() -> Self {
        Self {
            plugin_directory: PathBuf::from("plugins"),
            enable_experimental_plugins: false,
            require_plugin_signatures: true,
            max_concurrent_analyses: 10,
            analysis_timeout_seconds: 300,
            cache_size_mb: 512,
            logging_level: "info".to_string(),
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 1024,
            max_cpu_time_seconds: 300,
            max_disk_io_mb: 100,
            max_network_requests: 0,
            allow_file_system_access: false,
            allow_network_access: false,
        }
    }
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            confidence_threshold: 0.7,
            enable_deep_analysis: false,
            enable_correlation: false,
            enable_provenance_tracking: true,
            output_format: OutputFormat::Json,
            include_raw_data: false,
            anonymize_results: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_core_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = CoreConfiguration {
            plugin_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let core = ForensicCore::new(config).unwrap();
        assert_eq!(core.active_engines.len(), 0);
        assert_eq!(core.version.major, 1);
    }
    
    #[test]
    fn test_analysis_request_validation() {
        let temp_dir = TempDir::new().unwrap();
        let config = CoreConfiguration {
            plugin_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let core = ForensicCore::new(config).unwrap();
        
        let request = AnalysisRequest {
            request_id: Uuid::new_v4(),
            input_data: AnalysisInput::SourceCode {
                content: "fn main() {}".to_string(),
                language: "rust".to_string(),
                file_path: None,
            },
            requested_engines: vec!["nonexistent_engine".to_string()],
            analysis_options: AnalysisOptions::default(),
            context: ExecutionContext {
                context_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                investigator_id: "test".to_string(),
                case_id: "test".to_string(),
                security_level: SecurityLevel::Public,
                resource_limits: ResourceLimits::default(),
                environment: HashMap::new(),
                created_at: chrono::Utc::now(),
            },
            priority: RequestPriority::Normal,
        };
        
        let result = core.validate_request(&request);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_system_status() {
        let temp_dir = TempDir::new().unwrap();
        let config = CoreConfiguration {
            plugin_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let core = ForensicCore::new(config).unwrap();
        let status = core.get_system_status();
        
        assert_eq!(status.loaded_plugins, 0);
        assert_eq!(status.active_engines, 0);
        assert!(matches!(status.system_health, SystemHealth::Healthy));
    }

    #[test]
    fn test_plugin_engine_registration() {
        let temp_dir = TempDir::new().unwrap();
        let config = CoreConfiguration {
            plugin_directory: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        
        let mut core = ForensicCore::new(config).unwrap();
        
        core.governance.approve_plugin(
            "test_plugin".to_string(),
            "1.0.0".to_string(),
            vec!["admin".to_string()],
        ).unwrap();
        
        let plugin = Plugin {
            metadata: PluginMetadata::default_for_name("test_plugin".to_string()),
            library_path: temp_dir.path().join("test_plugin.so"),
            loaded: false,
        };
        
        let engine = plugin.build_engine().unwrap();
        let engine_id = engine.id().to_string();
        
        core.plugin_registry.register_engine(engine).unwrap();
        core.plugin_registry.register_plugin(plugin).unwrap();
        
        assert_eq!(core.plugin_registry.list_engines().len(), 1);
        assert!(core.plugin_registry.get_engine(&engine_id).is_some());
    }
}