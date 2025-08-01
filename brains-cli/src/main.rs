//! Tumunu Brains CLI
//! 
//! Command-line interface for forensic analysis with investigation session recording.

// Core dependencies
use std::{fs, path::PathBuf, io::Write};
use anyhow::{anyhow, Context, Result as AnyResult};
use brains_memory::{MemoryEntry, MemoryStore};
use rand::Rng;
use ed25519_dalek::Signer;
use sysinfo::{SystemExt, ProcessExt};

// External crates
use clap::Parser;
use console::style;
use tracing::{info, warn};
use std::process::Command;

// Project modules
use brains_detection::{
    AnalysisSession, BasicLLMDetector,
    DetectionResult, Evidence, EvidenceType, CodeLocation,
    UserAnnotation, ValidationStatus, Provenance
};
use brains_forensics::{PatternMatch, ASTPatternAnalyzer};
use brains_provenance::ProvenanceFingerprinter;
use brains_core::{ScanOptions, SourceFile, collect_source_files, default_ext_map, parse_ext_map_config, merge_ext_maps};
use uuid::Uuid;

// CLI specific
use clap::Subcommand;

/// Output stream abstraction for clean separation of data and status streams
struct Output {
    data_out: Box<dyn Write + Send>,
    status_out: Box<dyn Write + Send>,
    quiet: bool,
    no_banner: bool,
}

impl Output {
    fn new(quiet: bool, no_banner: bool) -> Self {
        Self {
            data_out: Box::new(std::io::stdout()),
            status_out: Box::new(std::io::stderr()),
            quiet,
            no_banner,
        }
    }
    
    fn write_data(&mut self, content: &str) -> Result<(), std::io::Error> {
        writeln!(self.data_out, "{}", content)?;
        self.data_out.flush()
    }
    
    fn write_status(&mut self, message: &str) -> Result<(), std::io::Error> {
        if !self.quiet {
            writeln!(self.status_out, "{}", message)?;
            self.status_out.flush()?;
        }
        Ok(())
    }
    
    fn banner(&mut self, message: &str) -> Result<(), std::io::Error> {
        if !self.no_banner && !self.quiet {
            writeln!(self.status_out, "{}", message)?;
            self.status_out.flush()?;
        }
        Ok(())
    }
    
    fn warn(&mut self, message: &str) -> Result<(), std::io::Error> {
        writeln!(self.status_out, "{}", message)?;
        self.status_out.flush()
    }
    
    fn error(&mut self, message: &str) -> Result<(), std::io::Error> {
        writeln!(self.status_out, "{}", message)?;
        self.status_out.flush()
    }
}

/// Output format enumeration
#[derive(Debug, Clone)]
enum OutputFormat {
    Json,
    Yaml,
    Markdown,
    Table,
    Human,
}

impl OutputFormat {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            "yaml" | "yml" => Self::Yaml,
            "markdown" | "md" => Self::Markdown,
            "table" => Self::Table,
            _ => Self::Human,
        }
    }
}

/// Render payload to output stream based on format
fn render_payload<T: serde::Serialize + std::fmt::Debug>(
    format: &OutputFormat,
    value: &T,
    output: &mut Output,
) -> AnyResult<()> {
    match format {
        OutputFormat::Json => {
            let json_str = serde_json::to_string_pretty(value)
                .context("Failed to serialize to JSON")?;
            output.write_data(&json_str)?;
        }
        OutputFormat::Yaml => {
            let yaml_str = serde_yaml::to_string(value)
                .context("Failed to serialize to YAML")?;
            output.write_data(&yaml_str)?;
        }
        OutputFormat::Markdown | OutputFormat::Table | OutputFormat::Human => {
            let content = format!("{:#?}", value);
            output.write_data(&content)?;
        }
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "brains")]
#[command(about = "Tumunu Brains: Forensic Intelligence Platform for Code Analysis")]
#[command(version = "0.1.0")]
#[command(author = "Tumunu Research")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Suppress progress and informational messages (errors still shown)
    #[arg(short, long)]
    quiet: bool,
    
    /// Suppress startup banner
    #[arg(long)]
    no_banner: bool,
    
    /// Investigation session file
    #[arg(short, long, default_value = "session.json")]
    session: PathBuf,
    
    /// Investigator ID
    #[arg(long, default_value = "researcher")]
    investigator: String,
    
    /// Case ID
    #[arg(long, default_value = "case-001")]
    case_id: String,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Forensic analysis operations
    Forensics {
        #[command(subcommand)]
        action: ForensicsAction,
    },

    /// Server control operations
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    /// Generate forensic report
    Report {
        /// Session file to generate report from
        #[arg(short, long)]
        session: Option<PathBuf>,
        
        /// Output format (markdown, pdf, json)
        #[arg(short, long, default_value = "markdown")]
        format: String,
        
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand, Clone)]
enum MemoryAction {
    /// Add a new memory entry
    Add {
        /// Problem description
        problem: String,
        
        /// Solution/analysis
        solution: String,
        
        /// Category tag
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Search memories
    Search {
        /// Query string
        query: String,
        
        /// Confidence threshold (0.0-1.0)
        #[arg(short, long, default_value = "0.7")]
        confidence_threshold: f64,
    },

    /// List memories
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
        
        /// Output format (table, json, yaml)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
}

#[derive(Subcommand, Clone)]
enum ForensicsAction {
    /// Analyze code for patterns
    Analyze {
        /// Path to code/file to analyze
        #[arg(long, default_value = ".")]
        path: PathBuf,
        
        /// Pattern type to detect (llm, surveillance, vulnerability)
        #[arg(short, long, default_value = "llm")]
        pattern_type: String,
        
        /// Recursive directory analysis
        #[arg(short, long)]
        recursive: bool,
        
        /// Include patterns (glob, repeatable)
        #[arg(long, action = clap::ArgAction::Append)]
        include: Vec<String>,
        
        /// Exclude patterns (glob, repeatable)
        #[arg(long, action = clap::ArgAction::Append)]
        exclude: Vec<String>,
        
        /// Maximum file size in bytes
        #[arg(long)]
        max_file_size: Option<u64>,
        
        /// Language extension mapping (file path or inline JSON)
        #[arg(long)]
        lang_ext_map: Option<String>,
        
        /// Follow symbolic links
        #[arg(long)]
        follow_symlinks: bool,
        
        /// Include hidden files and directories
        #[arg(long)]
        hidden: bool,
        
        /// Respect .gitignore files
        #[arg(long, default_value = "true")]
        respect_gitignore: bool,
        
        /// Print discovered files for verification
        #[arg(long)]
        print_files: bool,
        
        /// Minimum confidence threshold (0.0-1.0)
        #[arg(long, default_value = "0.5")]
        confidence: f64,
        
        /// Output format (json, yaml, markdown, table)
        #[arg(short, long, default_value = "table")]
        format: String,
        
        /// Include AST statistics in output
        #[arg(long)]
        stats: bool,
        
        /// Filter by specific pattern names (comma-separated)
        #[arg(long)]
        patterns: Option<String>,
    },

    /// Detect surveillance artifacts
    Detect {
        /// Artifacts to analyze
        artifacts: PathBuf,
        
        /// Surveillance type to detect
        #[arg(short = 't', long, default_value = "generic")]
        surveillance_type: String,
        
        /// Run in sandboxed environment
        #[arg(short = 'b', long)]
        sandbox: bool,
    },

    /// Classify samples
    Classify {
        /// Samples to classify
        samples: PathBuf,
        
        /// Output format (json, yaml, markdown)
        #[arg(short, long, default_value = "json")]
        format: String,
        
        /// Include explainable rationale
        #[arg(short, long)]
        explainable: bool,
    },
}

#[derive(Subcommand, Clone)]
enum ServerAction {
    /// Start the server
    Start {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
        
        /// Config file path
        #[arg(short, long)]
        config: Option<PathBuf>,
        
        /// Run in airgapped mode
        #[arg(short, long)]
        airgapped: bool,
    },

    /// Stop the server
    Stop,

    /// Check server status
    Status,
}

#[derive(Subcommand, Clone)]
enum SessionAction {
    /// Create a new session
    New,
    
    /// Continue existing session
    Continue,
    
    /// Annotate previous results
    Annotate {
        /// Result ID to annotate
        result_id: String,
        
        /// Annotation text
        annotation: String,
        
        /// Validation status
        #[arg(short, long, default_value = "confirmed")]
        status: String,
    },
    
    /// Export session data
    Export {
        /// Export format
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}

/// Investigation context
struct Investigation {
    session: AnalysisSession,
    detector: BasicLLMDetector,
    fingerprinter: ProvenanceFingerprinter,
    session_path: PathBuf,
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    let args = Cli::parse();
    
    // Create output abstraction for stream separation
    let mut output = Output::new(args.quiet, args.no_banner);
    
    // Set up logging based on verbosity
    let log_level = match args.verbose {
        true => "debug",
        false => "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();
    
    info!("Launching CLI tool");
    
    // Handle different command cases
    match args.command.clone() {
        Commands::Forensics { action } => match action {
            ForensicsAction::Analyze {
                path,
                pattern_type,
                recursive,
                include,
                exclude,
                max_file_size,
                lang_ext_map,
                follow_symlinks,
                hidden,
                respect_gitignore,
                print_files,
                confidence,
                format,
                stats,
                patterns
            } => {
                analyze_command(
                    &mut output,
                    args,
                    path,
                    pattern_type,
                    recursive,
                    include,
                    exclude,
                    max_file_size,
                    lang_ext_map,
                    follow_symlinks,
                    hidden,
                    respect_gitignore,
                    print_files,
                    confidence,
                    format,
                    stats,
                    patterns
                )
                .await
                .context("Analysis failed")?;
            }
            ForensicsAction::Detect { 
                artifacts, 
                surveillance_type, 
                sandbox 
            } => {
                detect_command(
                    &mut output,
                    args,
                    artifacts,
                    surveillance_type.to_string(),
                    sandbox
                )
                .await
                .context("Detection failed")?;
            }
            ForensicsAction::Classify { 
                samples, 
                format, 
                explainable 
            } => {
                classify_command(
                    &mut output,
                    args,
                    samples,
                    format.to_string(),
                    explainable
                )
                .await
                .context("Classification failed")?;
            }
        },
        Commands::Report { session, format, output: output_path } => {
            report_command(&mut output, args, session, format, output_path).await?;
        }
        Commands::Server { action } => {
            server_command(&mut output, args, action).await?;
        }
    }
    
    Ok(())
}

async fn analyze_command(
    output: &mut Output,
    args: Cli,
    path: PathBuf,
    pattern_type: String,
    recursive: bool,
    include: Vec<String>,
    exclude: Vec<String>,
    max_file_size: Option<u64>,
    lang_ext_map: Option<String>,
    follow_symlinks: bool,
    hidden: bool,
    respect_gitignore: bool,
    print_files: bool,
    confidence: f64,
    format: String,
    stats: bool,
    patterns: Option<String>,
) -> AnyResult<()> {
    // Setup analysis session
    output.banner(&format!("{}", style("Starting Forensic Analysis").bold().blue()))?;
    output.banner(&format!("{}", style("-".repeat(40)).dim()))?;
    
    let mut investigation = match load_or_create_investigation(args).await {
        Ok(inv) => inv,
        Err(e) => {
            output.error(&format!("Failed to load investigation: {}", e))?;
            return Err(e.into());
        }
    };

    // Build extension-to-language mapping
    let mut ext_lang_map = default_ext_map();
    if let Some(lang_map_input) = lang_ext_map {
        let overrides = parse_ext_map_config(&lang_map_input)
            .context("Failed to parse language extension mapping")?;
        ext_lang_map = merge_ext_maps(ext_lang_map, overrides);
    }

    // Build scan options
    let scan_opts = ScanOptions {
        root: path.clone(),
        recursive,
        include,
        exclude,
        max_file_size,
        follow_symlinks,
        include_hidden: hidden,
        respect_gitignore,
        ext_lang_map,
    };

    // Collect source files using the new fs_scanner
    let source_files = collect_source_files(&scan_opts)
        .context("Failed to collect source files")?;

    // Print files if requested for verification
    if print_files {
        output.write_status(&format!("{}", style("Discovered files:").bold().green()))?;
        for file in &source_files {
            output.write_status(&format!("{}", serde_json::json!({
                "rel_path": file.rel_path,
                "language": file.language,
                "size": file.size
            })))?;
        }
        output.write_status("")?;
    }

    // Process files for analysis
    let mut analyzer = ASTPatternAnalyzer::new()?;
    let mut all_results: Vec<DetectionResult> = Vec::new();
    let mut all_stats = Vec::new();

    for source_file in &source_files {
        output.write_status(&format!("Analyzing: {}", style(source_file.rel_path.display()).yellow()))?;
        
        let file_content = fs::read_to_string(&source_file.path)
            .with_context(|| format!("Failed to read file: {}", source_file.path.display()))?;
        
        // Run pattern analysis
        let matches = analyzer.analyze_code(&file_content, &source_file.language);
        
        // Filter matches
        let filtered_matches: Vec<PatternMatch> = matches.into_iter()
            .filter(|m| {
                // Confidence threshold
                m.confidence >= confidence &&
                // Pattern type filter
                (pattern_type == "all" ||
                 m.metadata.get("pattern_type").map_or(false, |pt| pt == &pattern_type)) &&
                // Specific patterns filter
                patterns.as_ref().map_or(true, |pats| {
                    pats.split(',').any(|p| m.pattern_name.contains(p))
                })
            })
            .collect();

        // Generate AST stats if requested
        if stats {
            let file_stats = format!("File: {}, Language: {}, Size: {} bytes", 
                source_file.rel_path.display(), source_file.language, source_file.size);
            all_stats.push(file_stats);
        }

        // Convert to detection results
        let results = filtered_matches.into_iter()
            .map(|m| {
                DetectionResult {
                    pattern_id: Uuid::new_v4(),
                    confidence: m.confidence,
                    evidence: vec![Evidence {
                        evidence_type: EvidenceType::SyntacticPattern {
                            pattern_name: m.pattern_name.clone(),
                        },
                        location: CodeLocation {
                            file_path: Some(source_file.rel_path.display().to_string()),
                            line_start: m.line_range.0,
                            line_end: m.line_range.1,
                            column_start: m.node_range.0,
                            column_end: m.node_range.1,
                            context: Some(m.context.clone()),
                        },
                        signature: m.evidence.clone(),
                        confidence: m.confidence,
                        metadata: match m.metadata.as_object() {
                            Some(obj) => obj.iter()
                                .map(|(k, v)| (k.clone(), v.to_string()))
                                .collect(),
                            None => std::collections::HashMap::new(),
                        },
                    }],
                    provenance: Provenance {
                        git_hash: None,
                        build_id: "fs_scanner_v1".to_string(),
                        timestamp: chrono::Utc::now(),
                        analyzer_version: "0.1.0".to_string(),
                        environment_fingerprint: "fs_scanner_env".to_string(),
                        input_hash: format!("{:x}", md5::compute(&file_content)),
                    },
                    rationale: format!("AST pattern match: {}", m.pattern_name),
                    ontology_tags: vec!["ast_pattern".to_string(), "syntactic".to_string()],
                    detection_timestamp: chrono::Utc::now(),
                }
            })
            .collect::<Vec<DetectionResult>>();

        all_results.extend(results);
    }

    // Save results to investigation
    for result in &all_results {
        investigation.session.add_result(result.clone());
    }
    save_investigation(&investigation).await?;

    // Generate completion status
    output.write_status(&format!("\n{}", style(format!("Analysis complete. Found {} files, {} results", 
        source_files.len(), all_results.len())).bold().green()))?;

    // Render final output
    let output_format = OutputFormat::from_str(&format);
    
    match output_format {
        OutputFormat::Json => {
            let payload = if stats {
                serde_json::json!({
                    "results": all_results,
                    "statistics": all_stats
                })
            } else {
                serde_json::json!(all_results)
            };
            render_payload(&output_format, &payload, output)?;
        }
        OutputFormat::Yaml => {
            let payload = if stats {
                serde_json::json!({
                    "results": all_results,
                    "statistics": all_stats
                })
            } else {
                serde_json::json!(all_results)
            };
            render_payload(&output_format, &payload, output)?;
        }
        OutputFormat::Markdown => {
            print_markdown_report(output, &all_results, all_stats.as_slice())?;
        }
        OutputFormat::Table => {
            print_table_output(output, &all_results)?;
        }
        OutputFormat::Human => {
            output.warn(&format!("Unsupported format '{}', defaulting to table", format))?;
            print_table_output(output, &all_results)?;
        }
    }

    Ok(())
}

async fn session_command(cli: Cli, action: SessionAction) -> AnyResult<()> {
    match action {
        SessionAction::New => {
            println!("{}", style("🆕 Creating new investigation session").bold().green());
            let session = AnalysisSession::new(cli.investigator.clone(), cli.case_id.clone());
            let investigation = Investigation {
                session,
                detector: BasicLLMDetector::new(),
                fingerprinter: ProvenanceFingerprinter::new(),
                session_path: cli.session.clone(),
            };
            save_investigation(&investigation).await?;
            println!("✅ New session created: {}", style(&cli.case_id).cyan());
        }
        SessionAction::Continue => {
            println!("{}", style("Continuing existing session").bold().blue());
            let investigation = load_investigation(&cli.session).await?;
            println!("✅ Session loaded: {}", style(&investigation.session.case_id).cyan());
            println!("   Results: {}", investigation.session.results.len());
            println!("   Annotations: {}", investigation.session.annotations.len());
        }
        SessionAction::Annotate { result_id, annotation, status } => {
            println!("{}", style("Adding annotation").bold().yellow());
            let mut investigation = load_investigation(&cli.session).await?;
            
            let validation_status = match status.as_str() {
                "confirmed" => ValidationStatus::Confirmed,
                "disputed" => ValidationStatus::Disputed,
                "uncertain" => ValidationStatus::Uncertain,
                _ => ValidationStatus::RequiresReview,
            };
            
            // Generate signing key for investigator
            let mut csprng = rand::rngs::OsRng;
            let mut csprng = rand::rngs::OsRng;
            let mut key_bytes = [0u8; 32];
            csprng.fill(&mut key_bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            
            let mut annotation = UserAnnotation {
                annotation_id: Uuid::new_v4(),
                investigator_id: cli.investigator.clone(),
                target_id: Uuid::parse_str(&result_id)?,
                annotation_text: annotation,
                confidence_override: None,
                validation_status,
                timestamp: chrono::Utc::now(),
                signature: None,
            };

            // Sign the annotation
            let signature = signing_key.try_sign(
                format!("{}{}",
                    annotation.annotation_id,
                    annotation.annotation_text
                ).as_bytes()
            );
            
            match signature {
                Ok(sig) => annotation.signature = Some(sig.to_string()),
                Err(e) => return Err(anyhow!("Failed to sign annotation: {}", e)),
            }
            
            investigation.session.add_annotation(annotation);
            save_investigation(&investigation).await?;
            println!("✅ Annotation added");
        }
        SessionAction::Export { format } => {
            println!("{}", style("Exporting session data").bold().magenta());
            let investigation = load_investigation(&cli.session).await?;
            
            match format.as_str() {
                "json" => {
                    let output = serde_json::to_string_pretty(&investigation.session)?;
                    println!("{}", output);
                }
                "yaml" => {
                    let output = serde_yaml::to_string(&investigation.session)?;
                    println!("{}", output);
                }
                _ => {
                    return Err(anyhow::anyhow!("Unsupported export format: {}", format));
                }
            }
        }
    }
    
    Ok(())
}

async fn report_command(
    output_stream: &mut Output,
    cli: Cli,
    session: Option<PathBuf>,
    format: String,
    output: Option<PathBuf>,
) -> AnyResult<()> {
    output_stream.banner(&format!("{}", style("Generating forensic report").bold().green()))?;
    
    let session_path = session.unwrap_or(cli.session);
    let investigation = load_investigation(&session_path).await?;
    
    match format.as_str() {
        "markdown" => {
            let report = generate_markdown_report(&investigation.session)?;
            if let Some(output_path) = output {
                fs::write(&output_path, report)?;
                println!("✅ Report saved to: {}", style(output_path.display()).cyan());
            } else {
                println!("{}", report);
            }
        }
        "json" => {
            let report = serde_json::to_string_pretty(&investigation.session)?;
            if let Some(output_path) = output {
                fs::write(&output_path, report)?;
                println!("✅ Report saved to: {}", style(output_path.display()).cyan());
            } else {
                println!("{}", report);
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported report format: {}", format));
        }
    }
    
    Ok(())
}

async fn server_command(output: &mut Output, cli: Cli, action: ServerAction) -> AnyResult<()> {
    let pid_file = PathBuf::from("brains-server.pid");
    
    match action {
        ServerAction::Start { port, config, airgapped } => {
            println!("{}", style("Starting server...").bold().green());
            
            // Check if server is already running
            if pid_file.exists() {
                return Err(anyhow!("Server is already running"));
            }

            // Start server process
            let mut cmd = Command::new("brains-server");
            cmd.arg("--port").arg(port.to_string());
            
            if let Some(config_path) = &config {
                cmd.arg("--config").arg(config_path);
            }
            if airgapped {
                cmd.arg("--airgapped");
            }
            
            let child = cmd.spawn()?;
            
            // Write PID file
            fs::write(&pid_file, child.id().to_string())?;
            
            println!("{}", style(format!(
                "Server started (PID: {}) on port {}",
                child.id(),
                port
            )).bold());
        }
        ServerAction::Stop => {
            println!("{}", style("Stopping server...").bold().yellow());
            
            if !pid_file.exists() {
                return Err(anyhow!("No server running"));
            }
            
            let pid = fs::read_to_string(&pid_file)?;
            let pid = pid.parse::<u32>()?;
            
            // Send SIGTERM to process
            #[cfg(unix)]
            {
                use sysinfo::Pid;
                let mut system = sysinfo::System::new();
                system.refresh_all();
                if let Some(process) = system.process(Pid::from(pid as usize)) {
                    if !process.kill() {
                        return Err(anyhow!("Failed to kill process"));
                    }
                }
            }
            
            #[cfg(windows)]
            {
                Command::new("taskkill")
                    .arg("/PID")
                    .arg(pid.to_string())
                    .status()?;
            }
            
            fs::remove_file(&pid_file)?;
            println!("{}", style("Server stopped successfully").bold());
        }
        ServerAction::Status => {
            if pid_file.exists() {
                let pid = fs::read_to_string(&pid_file)?;
                println!("{}", style(format!(
                    "Server is running (PID: {})",
                    pid
                )).bold().green());
            } else {
                println!("{}", style("Server is not running").bold().red());
            }
        }
    }
    Ok(())
}

/// Helper function to collect files using legacy path-based interface
/// This maintains backward compatibility for commands that haven't been fully migrated
fn collect_files_legacy(path: &PathBuf, recursive: bool) -> AnyResult<Vec<SourceFile>> {
    let scan_opts = ScanOptions {
        root: path.clone(),
        recursive,
        include: Vec::new(),
        exclude: Vec::new(),
        max_file_size: None,
        follow_symlinks: false,
        include_hidden: false,
        respect_gitignore: true,
        ext_lang_map: default_ext_map(),
    };
    
    collect_source_files(&scan_opts)
        .context("Failed to collect source files")
}

async fn validate_command(
    cli: Cli,
    dataset: PathBuf,
    model: String,
    folds: usize,
) -> anyhow::Result<()> {
    println!("{}", style("Validating detection model").bold().blue());
    println!("Dataset: {}", style(dataset.display()).yellow());
    println!("Model: {}", style(&model).cyan());
    println!("Cross-validation folds: {}", folds);
    
    if !dataset.exists() {
        return Err(anyhow::anyhow!("Dataset path does not exist: {}", dataset.display()));
    }
    
    let mut investigation = load_or_create_investigation(cli).await?;
    let mut analyzer = ASTPatternAnalyzer::new()?;
    
    // Collect dataset files
    let dataset_files = if dataset.is_dir() {
        collect_files_legacy(&dataset, true)?
    } else {
        // For single files, create a minimal SourceFile entry
        vec![SourceFile {
            path: dataset.clone(),
            rel_path: dataset.file_name().unwrap_or_default().into(),
            language: "unknown".to_string(),
            size: dataset.metadata().map(|m| m.len()).unwrap_or(0),
        }]
    };
    
    if dataset_files.is_empty() {
        return Err(anyhow::anyhow!("No valid source files found in dataset"));
    }
    
    println!("Found {} files for validation", dataset_files.len());
    
    // Perform k-fold cross-validation
    let fold_size = dataset_files.len() / folds;
    let mut total_accuracy = 0.0;
    let mut total_precision = 0.0;
    let mut total_recall = 0.0;
    
    for fold in 0..folds {
        println!("Running fold {}/{}", fold + 1, folds);
        
        let start_idx = fold * fold_size;
        let end_idx = if fold == folds - 1 {
            dataset_files.len()
        } else {
            (fold + 1) * fold_size
        };
        
        // Split data into train and test sets
        let test_files = &dataset_files[start_idx..end_idx];
        let train_files: Vec<_> = dataset_files.iter()
            .enumerate()
            .filter(|(i, _)| *i < start_idx || *i >= end_idx)
            .map(|(_, file)| file)
            .collect();
        
        println!("  Training on {} files, testing on {} files", train_files.len(), test_files.len());
        
        // Evaluate model on test set
        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut true_negatives = 0;
        let mut false_negatives = 0;
        
        for test_file in test_files {
            let file_content = fs::read_to_string(&test_file.path)?;
            let matches = analyzer.analyze_code(&file_content, &test_file.language);
            
            // Determine ground truth based on filename or content
            let is_positive = test_file.path.to_string_lossy().contains("positive") || 
                             test_file.path.to_string_lossy().contains("suspicious") ||
                             matches.iter().any(|m| m.confidence > 0.8);
            
            // Determine prediction based on model
            let prediction = match model.as_str() {
                "conservative" => matches.iter().any(|m| m.confidence > 0.9),
                "balanced" => matches.iter().any(|m| m.confidence > 0.7),
                "aggressive" => matches.iter().any(|m| m.confidence > 0.5),
                _ => matches.iter().any(|m| m.confidence > 0.7),
            };
            
            match (is_positive, prediction) {
                (true, true) => true_positives += 1,
                (true, false) => false_negatives += 1,
                (false, true) => false_positives += 1,
                (false, false) => true_negatives += 1,
            }
        }
        
        // Calculate metrics for this fold
        let accuracy = (true_positives + true_negatives) as f64 / test_files.len() as f64;
        let precision = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            0.0
        };
        let recall = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            0.0
        };
        
        println!("  Fold {} results:", fold + 1);
        println!("    Accuracy: {:.3}", accuracy);
        println!("    Precision: {:.3}", precision);
        println!("    Recall: {:.3}", recall);
        
        total_accuracy += accuracy;
        total_precision += precision;
        total_recall += recall;
    }
    
    // Calculate final metrics
    let avg_accuracy = total_accuracy / folds as f64;
    let avg_precision = total_precision / folds as f64;
    let avg_recall = total_recall / folds as f64;
    let f1_score = if avg_precision + avg_recall > 0.0 {
        2.0 * (avg_precision * avg_recall) / (avg_precision + avg_recall)
    } else {
        0.0
    };
    
    println!("\n{}", style("Final Cross-Validation Results").bold().green());
    println!("Average Accuracy: {:.3}", avg_accuracy);
    println!("Average Precision: {:.3}", avg_precision);
    println!("Average Recall: {:.3}", avg_recall);
    println!("F1 Score: {:.3}", f1_score);
    
    // Save validation results to investigation
    let validation_result = DetectionResult {
        pattern_id: Uuid::new_v4(),
        confidence: avg_accuracy,
        evidence: vec![Evidence {
            evidence_type: EvidenceType::SyntacticPattern {
                pattern_name: "ModelValidation".to_string(),
            },
            location: CodeLocation {
                file_path: Some(dataset.display().to_string()),
                line_start: 0,
                line_end: 0,
                column_start: 0,
                column_end: 0,
                context: Some(format!("Model: {}, Folds: {}", model, folds)),
            },
            signature: format!("Validation-{}-{}", model, folds),
            confidence: avg_accuracy,
            metadata: {
                let mut metadata = std::collections::HashMap::new();
                metadata.insert("model".to_string(), model.clone());
                metadata.insert("folds".to_string(), folds.to_string());
                metadata.insert("precision".to_string(), format!("{:.3}", avg_precision));
                metadata.insert("recall".to_string(), format!("{:.3}", avg_recall));
                metadata.insert("f1_score".to_string(), format!("{:.3}", f1_score));
                metadata
            },
        }],
        provenance: Provenance {
            git_hash: None,
            build_id: "model_validator_v1".to_string(),
            timestamp: chrono::Utc::now(),
            analyzer_version: "0.1.0".to_string(),
            environment_fingerprint: "validation_env".to_string(),
            input_hash: format!("{:x}", md5::compute(dataset.display().to_string())),
        },
        rationale: format!("Cross-validation results for {} model: Accuracy={:.3}, F1={:.3}", model, avg_accuracy, f1_score),
        ontology_tags: vec!["validation".to_string(), "cross_validation".to_string()],
        detection_timestamp: chrono::Utc::now(),
    };
    
    investigation.session.add_result(validation_result);
    save_investigation(&investigation).await?;
    
    Ok(())
}

async fn load_or_create_investigation(cli: Cli) -> anyhow::Result<Investigation> {
    if cli.session.exists() {
        load_investigation(&cli.session).await
    } else {
        let session = AnalysisSession::new(cli.investigator, cli.case_id);
        Ok(Investigation {
            session,
            detector: BasicLLMDetector::new(),
            fingerprinter: ProvenanceFingerprinter::new(),
            session_path: cli.session.clone(),
        })
    }
}

async fn load_investigation(path: &PathBuf) -> anyhow::Result<Investigation> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read session file: {}", path.display()))?;
    let session: AnalysisSession = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse session JSON: {}", path.display()))?;
    
    Ok(Investigation {
        session,
        detector: BasicLLMDetector::new(),
        fingerprinter: ProvenanceFingerprinter::new(),
        session_path: path.clone(),
    })
}

async fn save_investigation(investigation: &Investigation) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(&investigation.session)?;
    save_json_atomically(&investigation.session_path, content.as_bytes())
}

fn save_json_atomically(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."), // Use current directory if path has no parent or empty parent
    };
    
    if !parent.is_dir() {
        return Err(anyhow::anyhow!(
            "Session save failed: parent directory does not exist or is not a directory: {}. Create it or choose a valid path with --session.",
            parent.display()
        ));
    }
    
    let final_name = path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("session");
    let tmp_name = format!(".{}.tmp-{}", final_name, rand::thread_rng().gen::<u32>());
    let tmp_path = parent.join(tmp_name);
    
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("Failed to create temp session file: {}", tmp_path.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("Failed to write temp session file: {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("Failed to fsync temp session file: {}", tmp_path.display()))?;
    }
    
    if let Ok(dir) = std::fs::OpenOptions::new().read(true).open(parent) {
        let _ = dir.sync_all();
    }
    
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to atomically replace {} with {}", path.display(), tmp_path.display()))?;
    
    if let Ok(dir) = std::fs::OpenOptions::new().read(true).open(parent) {
        let _ = dir.sync_all();
    }
    
    Ok(())
}



fn print_table_output(output: &mut Output, results: &[DetectionResult]) -> Result<(), std::io::Error> {
    use tabled::builder::Builder;
    
    let mut builder = Builder::default();
    builder.push_record(["Pattern", "Confidence", "Location", "Evidence"]);
    
    for result in results {
        let location = if let Some(evidence) = result.evidence.first() {
            format!("{}:{}",
                evidence.location.file_path.as_deref().unwrap_or("unknown"),
                evidence.location.line_start
            )
        } else {
            "unknown".to_string()
        };
        
        builder.push_record([
            &result.rationale,
            &format!("{:.2}", result.confidence),
            &location,
            &result.evidence.len().to_string()
        ]);
    }
    
    output.write_data(&format!("{}", builder.build()))
}

fn print_markdown_report(
    output: &mut Output,
    results: &Vec<DetectionResult>,
    _stats: &[String],
) -> Result<(), std::io::Error> {
    let mut markdown = String::new();
    markdown.push_str("# Forensic Analysis Report\n\n");
    markdown.push_str("## Detection Results\n");
    markdown.push_str(&format!("- **Total Results**: {}\n\n", results.len()));
    
    for (i, result) in results.iter().enumerate() {
        markdown.push_str(&format!("### Result {}\n", i + 1));
        markdown.push_str(&format!("- **Confidence**: {:.3}\n", result.confidence));
        markdown.push_str(&format!("- **Pattern ID**: {}\n", result.pattern_id));
        markdown.push_str(&format!("- **Evidence Count**: {}\n", result.evidence.len()));
        markdown.push_str(&format!("- **Rationale**: {}\n\n", result.rationale));
        
        markdown.push_str("#### Metadata\n");
        markdown.push_str(&format!("- **Analysis Timestamp**: {}\n", result.detection_timestamp));
        markdown.push_str(&format!("- **Analyzer Version**: {}\n", result.provenance.analyzer_version));
        markdown.push_str(&format!("- **Input Hash**: {}\n\n", result.provenance.input_hash));
    }
    
    output.write_data(&markdown)
}

async fn detect_command(
    output: &mut Output,
    args: Cli,
    artifacts: PathBuf,
    surveillance_type: String,
    sandbox: bool,
) -> AnyResult<()> {
    output.banner(&format!("{}", style("Starting surveillance detection analysis").bold().blue()))?;
    output.banner(&format!("{}", style("-".repeat(50)).dim()))?;
    
    // Validate input path
    if !artifacts.exists() {
        return Err(anyhow!("Artifacts path does not exist: {}", artifacts.display()));
    }
    
    // Load investigation session
    let mut investigation = load_or_create_investigation(args).await?;
    
    println!("Analyzing artifacts: {}", style(artifacts.display()).yellow());
    println!("Surveillance type: {}", style(&surveillance_type).cyan());
    println!("Sandbox mode: {}", style(sandbox).magenta());
    
    // Initialize pattern analyzer
    let mut analyzer = ASTPatternAnalyzer::new()?;
    let mut detection_results = Vec::new();
    
    // Process artifacts
    let files = if artifacts.is_dir() {
        collect_files_legacy(&artifacts, true)?
    } else {
        vec![SourceFile {
            path: artifacts.clone(),
            rel_path: artifacts.file_name().unwrap_or_default().into(),
            language: "unknown".to_string(),
            size: artifacts.metadata().map(|m| m.len()).unwrap_or(0),
        }]
    };
    
    for source_file in files {
        println!("Scanning: {}", style(source_file.rel_path.display()).yellow());
        
        let file_content = match fs::read_to_string(&source_file.path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read file {}: {}", source_file.path.display(), e);
                continue;
            }
        };
        
        let matches = analyzer.analyze_code(&file_content, &source_file.language);
        
        // Filter matches for surveillance patterns
        let surveillance_matches: Vec<PatternMatch> = matches.into_iter()
            .filter(|m| {
                // Look for surveillance-related patterns
                let pattern_lower = m.pattern_name.to_lowercase();
                let content_lower = m.context.to_lowercase();
                
                match surveillance_type.as_str() {
                    "network" => pattern_lower.contains("network") || content_lower.contains("socket") || content_lower.contains("tcp"),
                    "filesystem" => pattern_lower.contains("file") || content_lower.contains("fs") || content_lower.contains("path"),
                    "process" => pattern_lower.contains("process") || content_lower.contains("exec") || content_lower.contains("spawn"),
                    "generic" => pattern_lower.contains("monitor") || pattern_lower.contains("track") || pattern_lower.contains("collect"),
                    _ => true, // Default to include all patterns
                }
            })
            .collect();
        
        // Convert matches to detection results
        for pattern_match in surveillance_matches {
            let detection_result = DetectionResult {
                pattern_id: Uuid::new_v4(),
                confidence: pattern_match.confidence,
                evidence: vec![Evidence {
                    evidence_type: EvidenceType::SyntacticPattern {
                        pattern_name: pattern_match.pattern_name.clone(),
                    },
                    location: CodeLocation {
                        file_path: Some(source_file.rel_path.display().to_string()),
                        line_start: pattern_match.line_range.0,
                        line_end: pattern_match.line_range.1,
                        column_start: pattern_match.node_range.0,
                        column_end: pattern_match.node_range.1,
                        context: Some(pattern_match.context.clone()),
                    },
                    signature: pattern_match.evidence.clone(),
                    confidence: pattern_match.confidence,
                    metadata: match pattern_match.metadata.as_object() {
                        Some(obj) => obj.iter()
                            .map(|(k, v)| (k.clone(), v.to_string()))
                            .collect(),
                        None => std::collections::HashMap::new(),
                    },
                }],
                provenance: Provenance {
                    git_hash: None,
                    build_id: "surveillance_detector_v1".to_string(),
                    timestamp: chrono::Utc::now(),
                    analyzer_version: "0.1.0".to_string(),
                    environment_fingerprint: if sandbox { "sandbox" } else { "production" }.to_string(),
                    input_hash: format!("{:x}", md5::compute(&file_content)),
                },
                rationale: format!("Surveillance pattern detected: {} (type: {})", pattern_match.pattern_name, surveillance_type),
                ontology_tags: vec!["surveillance".to_string(), surveillance_type.clone()],
                detection_timestamp: chrono::Utc::now(),
            };
            
            detection_results.push(detection_result);
        }
    }
    
    // Save results to investigation
    for result in &detection_results {
        investigation.session.add_result(result.clone());
    }
    save_investigation(&investigation).await?;
    
    // Display results
    output.write_status(&format!("\n{}", style("Detection Summary").bold().green()))?;
    output.write_status(&format!("Total surveillance artifacts detected: {}", style(detection_results.len()).bold()))?;
    
    if !detection_results.is_empty() {
        print_table_output(output, &detection_results)?;
    } else {
        output.write_status(&format!("{}", style("No surveillance artifacts detected").dim()))?;
    }
    
    Ok(())
}

async fn classify_command(
    output: &mut Output,
    args: Cli,
    samples: PathBuf,
    format: String,
    explainable: bool,
) -> AnyResult<()> {
    output.banner(&format!("{}", style("Starting sample classification").bold().blue()))?;
    output.banner(&format!("{}", style("-".repeat(40)).dim()))?;
    
    // Validate input path
    if !samples.exists() {
        return Err(anyhow!("Samples path does not exist: {}", samples.display()));
    }
    
    // Load investigation session
    let mut investigation = load_or_create_investigation(args).await?;
    
    println!("Classifying samples: {}", style(samples.display()).yellow());
    println!("Output format: {}", style(&format).cyan());
    println!("Explainable: {}", style(explainable).magenta());
    
    // Initialize analyzers
    let mut analyzer = ASTPatternAnalyzer::new()?;
    let mut classification_results = Vec::new();
    
    // Process samples
    let files = if samples.is_dir() {
        collect_files_legacy(&samples, true)?
    } else {
        vec![SourceFile {
            path: samples.clone(),
            rel_path: samples.file_name().unwrap_or_default().into(),
            language: "unknown".to_string(),
            size: samples.metadata().map(|m| m.len()).unwrap_or(0),
        }]
    };
    
    for source_file in files {
        println!("Classifying: {}", style(source_file.rel_path.display()).yellow());
        
        let file_content = match fs::read_to_string(&source_file.path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read file {}: {}", source_file.path.display(), e);
                continue;
            }
        };
        
        let matches = analyzer.analyze_code(&file_content, &source_file.language);
        
        // Classify based on pattern analysis
        let mut classification = "benign".to_string();
        let mut confidence = 0.0;
        let mut rationale = "No suspicious patterns detected".to_string();
        
        if !matches.is_empty() {
            let max_confidence = matches.iter().map(|m| m.confidence).fold(0.0, f64::max);
            let suspicious_patterns: Vec<&PatternMatch> = matches.iter()
                .filter(|m| m.confidence > 0.7)
                .collect();
            
            if !suspicious_patterns.is_empty() {
                classification = "suspicious".to_string();
                confidence = max_confidence;
                rationale = format!("Detected {} high-confidence suspicious patterns", suspicious_patterns.len());
                
                if explainable {
                    rationale.push_str(&format!(" - Patterns: {}", 
                        suspicious_patterns.iter()
                            .map(|p| p.pattern_name.as_str())
                            .collect::<Vec<&str>>()
                            .join(", ")
                    ));
                }
            } else {
                classification = "low_risk".to_string();
                confidence = max_confidence;
                rationale = format!("Detected {} low-confidence patterns", matches.len());
            }
        }
        
        // Create classification result
        let classification_result = DetectionResult {
            pattern_id: Uuid::new_v4(),
            confidence,
            evidence: matches.into_iter().map(|m| Evidence {
                evidence_type: EvidenceType::SyntacticPattern {
                    pattern_name: m.pattern_name.clone(),
                },
                location: CodeLocation {
                    file_path: Some(source_file.rel_path.display().to_string()),
                    line_start: m.line_range.0,
                    line_end: m.line_range.1,
                    column_start: m.node_range.0,
                    column_end: m.node_range.1,
                    context: Some(m.context.clone()),
                },
                signature: m.evidence.clone(),
                confidence: m.confidence,
                metadata: match m.metadata.as_object() {
                    Some(obj) => obj.iter()
                        .map(|(k, v)| (k.clone(), v.to_string()))
                        .collect(),
                    None => std::collections::HashMap::new(),
                },
            }).collect(),
            provenance: Provenance {
                git_hash: None,
                build_id: "sample_classifier_v1".to_string(),
                timestamp: chrono::Utc::now(),
                analyzer_version: "0.1.0".to_string(),
                environment_fingerprint: "classification_env".to_string(),
                input_hash: format!("{:x}", md5::compute(&file_content)),
            },
            rationale: rationale.clone(),
            ontology_tags: vec!["classification".to_string(), classification.clone()],
            detection_timestamp: chrono::Utc::now(),
        };
        
        classification_results.push(classification_result);
    }
    
    // Save results to investigation
    for result in &classification_results {
        investigation.session.add_result(result.clone());
    }
    save_investigation(&investigation).await?;
    
    // Generate output
    match format.as_str() {
        "json" => {
            let json_output = serde_json::to_string_pretty(&classification_results)?;
            output.write_data(&json_output)?;
        }
        "yaml" => {
            let yaml_output = serde_yaml::to_string(&classification_results)?;
            output.write_data(&yaml_output)?;
        }
        "markdown" => {
            print_markdown_report(output, &classification_results, &[])?;
        }
        _ => {
            output.warn(&format!("Unsupported format '{}', defaulting to table", format))?;
            print_table_output(output, &classification_results)?;
        }
    }
    
    Ok(())
}

fn generate_markdown_report(session: &AnalysisSession) -> anyhow::Result<String> {
    let mut report = String::new();
    
    report.push_str("# Forensic Investigation Report\n\n");
    report.push_str(&format!("**Case ID**: {}\n", session.case_id));
    report.push_str(&format!("**Investigator**: {}\n", session.investigator_id));
    report.push_str(&format!("**Session Started**: {}\n", session.started_at));
    report.push_str(&format!("**Reproducibility Hash**: {}\n\n", session.reproducibility_hash));
    
    report.push_str("## Analysis Summary\n\n");
    report.push_str(&format!("- **Inputs Analyzed**: {}\n", session.inputs.len()));
    report.push_str(&format!("- **Detection Results**: {}\n", session.results.len()));
    report.push_str(&format!("- **Annotations**: {}\n\n", session.annotations.len()));
    
    report.push_str("## Detection Results\n\n");
    for (i, result) in session.results.iter().enumerate() {
        report.push_str(&format!("### Result {}\n", i + 1));
        report.push_str(&format!("- **Confidence**: {:.3}\n", result.confidence));
        report.push_str(&format!("- **Evidence**: {} items\n", result.evidence.len()));
        report.push_str(&format!("- **Rationale**: {}\n\n", result.rationale));
    }
    
    if !session.annotations.is_empty() {
        report.push_str("## Annotations\n\n");
        for annotation in &session.annotations {
            report.push_str(&format!("- **{}**: {} ({})\n", 
                annotation.investigator_id, 
                annotation.annotation_text,
                format!("{:?}", annotation.validation_status)
            ));
        }
    }
    
    report.push_str("\n---\n");
    report.push_str("*Generated by Tumunu Brains*\n");
    
    Ok(report)
}
