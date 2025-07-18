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

pub use registry::PluginRegistry;
pub use plugin::{Plugin, PluginMetadata, PluginInterface};
pub use versioning::{ApiVersion, Compatibility};
pub use governance::{PluginGovernance, ApprovalStatus};

/// Core plugin system for forensic intelligence platform
#[derive(Serialize, Deserialize)]
pub struct ForensicCore {
    pub version: ApiVersion,
    pub plugin_registry: PluginRegistry,
    pub governance: PluginGovernance,
    #[serde(skip)]
    pub active_engines: HashMap<String, Box<dyn PatternEngine>>,
    pub configuration: CoreConfiguration,
}

impl Clone for ForensicCore {
    fn clone(&self) -> Self {
        Self {
            version: self.version.clone(),
            plugin_registry: self.plugin_registry.clone(),
            governance: self.governance.clone(),
            active_engines: HashMap::new(), // Cannot clone trait objects
            configuration: self.configuration.clone(),
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
        })
    }
    
    /// Load plugin from file
    pub fn load_plugin(&mut self, plugin_path: PathBuf) -> anyhow::Result<()> {
        let plugin = self.plugin_registry.load_plugin(plugin_path)?;
        
        // Check governance approval
        if !self.governance.is_approved(&plugin.metadata.name) {
            return Err(anyhow::anyhow!("Plugin not approved by governance: {}", plugin.metadata.name));
        }
        
        // Check API compatibility
        if !self.version.is_compatible(&plugin.metadata.api_version) {
            return Err(anyhow::anyhow!("Plugin API version incompatible: {} requires {}", 
                plugin.metadata.name, plugin.metadata.api_version));
        }
        
        // Register plugin
        self.plugin_registry.register_plugin(plugin)?;
        
        Ok(())
    }
    
    /// Execute analysis request
    pub async fn execute_analysis(&mut self, request: AnalysisRequest) -> anyhow::Result<AnalysisResponse> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::new();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut engine_times = HashMap::new();
        
        // Validate request
        self.validate_request(&request)?;
        
        // Execute requested engines
        for engine_name in &request.requested_engines {
            let engine_start = std::time::Instant::now();
            
            match self.execute_engine(engine_name, &request).await {
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
                memory_usage_mb: Self::get_memory_usage(),
                cpu_usage_percent: Self::get_cpu_usage(),
                disk_io_mb: 0.0,
                network_requests: 0,
                cache_hit_rate: 0.0,
            },
            execution_metadata: ExecutionMetadata {
                platform: std::env::consts::OS.to_string(),
                architecture: std::env::consts::ARCH.to_string(),
                rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
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
        
        // Check requested engines exist
        for engine_name in &request.requested_engines {
            if !self.active_engines.contains_key(engine_name) {
                return Err(anyhow::anyhow!("Engine not found: {}", engine_name));
            }
        }
        
        Ok(())
    }
    
    /// Execute specific engine
    async fn execute_engine(&self, engine_name: &str, request: &AnalysisRequest) -> anyhow::Result<Vec<DetectionResult>> {
        let engine = self.active_engines.get(engine_name)
            .ok_or_else(|| anyhow::anyhow!("Engine not found: {}", engine_name))?;
        
        // Extract code content from request
        let code = match &request.input_data {
            AnalysisInput::SourceCode { content, .. } => content.clone(),
            AnalysisInput::BinaryData { data, .. } => {
                // Convert binary to string for analysis
                String::from_utf8_lossy(data).to_string()
            }
            _ => return Err(anyhow::anyhow!("Unsupported input type for engine: {}", engine_name)),
        };
        
        // Execute engine analysis
        let results = engine.analyze(&code)?;
        
        // Filter results by confidence threshold
        let filtered_results = results.into_iter()
            .filter(|r| r.confidence >= request.analysis_options.confidence_threshold)
            .collect();
        
        Ok(filtered_results)
    }
    
    /// Get system status
    pub fn get_system_status(&self) -> SystemStatus {
        SystemStatus {
            version: self.version.clone(),
            loaded_plugins: self.plugin_registry.list_plugins().len(),
            active_engines: self.active_engines.len(),
            running_analyses: self.get_running_analyses_count(),
            system_health: SystemHealth::Healthy,
            resource_usage: ResourceUsage {
                memory_usage_mb: Self::get_memory_usage(),
                cpu_usage_percent: Self::get_cpu_usage(),
                disk_usage_mb: Self::get_disk_usage(),
                network_connections: 0,
            },
        }
    }
    
    /// Get current memory usage in MB
    fn get_memory_usage() -> f64 {
        use std::process::Command;
        
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    if let Ok(rss_kb) = output_str.trim().parse::<f64>() {
                        return rss_kb / 1024.0; // Convert KB to MB
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            if let Ok(output) = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", std::process::id()), "/FO", "CSV"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    // Parse CSV output for memory usage
                    for line in output_str.lines().skip(1) {
                        let fields: Vec<&str> = line.split(',').collect();
                        if fields.len() >= 5 {
                            let memory_str = fields[4].trim_matches('"').replace(",", "");
                            if let Ok(memory_kb) = memory_str.parse::<f64>() {
                                return memory_kb / 1024.0;
                            }
                        }
                    }
                }
            }
        }
        
        0.0
    }
    
    /// Get current CPU usage percentage
    fn get_cpu_usage() -> f64 {
        use std::process::Command;
        
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("ps")
                .args(["-o", "pcpu=", "-p", &std::process::id().to_string()])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    if let Ok(cpu_percent) = output_str.trim().parse::<f64>() {
                        return cpu_percent;
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            // Windows CPU usage is more complex to get in real-time
            // Return approximate value based on system load
            return 0.0;
        }
        
        0.0
    }
    
    /// Get current disk usage in MB
    fn get_disk_usage() -> f64 {
        use std::fs;
        
        if let Ok(metadata) = fs::metadata(".") {
            // This is a simplified approach - real implementation would
            // track actual disk I/O or workspace usage
            return 0.0;
        }
        
        0.0
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
}