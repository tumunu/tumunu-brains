//! File system scanner for forensic analysis
//! 
//! Provides configurable deep directory traversal with filtering capabilities
//! including glob patterns, file size limits, gitignore support, and language mapping.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Configuration options for file system scanning
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Root directory to scan from
    pub root: PathBuf,
    /// Whether to perform deep recursive traversal
    pub recursive: bool,
    /// Include patterns (glob) - if empty, include all
    pub include: Vec<String>,
    /// Exclude patterns (glob) - always applied
    pub exclude: Vec<String>,
    /// Maximum file size in bytes (None = no limit)
    pub max_file_size: Option<u64>,
    /// Whether to follow symbolic links
    pub follow_symlinks: bool,
    /// Whether to include hidden files and directories
    pub include_hidden: bool,
    /// Whether to respect .gitignore files
    pub respect_gitignore: bool,
    /// Extension to language mapping (lowercase extensions)
    pub ext_lang_map: HashMap<String, String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            recursive: false,
            include: Vec::new(),
            exclude: Vec::new(),
            max_file_size: None,
            follow_symlinks: false,
            include_hidden: false,
            respect_gitignore: true,
            ext_lang_map: default_ext_map(),
        }
    }
}

/// Represents a discovered source file with metadata
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Absolute/canonical path to the file
    pub path: PathBuf,
    /// Path relative to scan root (for stable output and glob matching)
    pub rel_path: PathBuf,
    /// Detected programming language
    pub language: String,
    /// File size in bytes
    pub size: u64,
}

/// Configuration for language extension mapping overrides
#[derive(Debug, Deserialize, Serialize)]
pub struct ExtensionMapConfig {
    /// Extension to language mappings
    pub extensions: HashMap<String, String>,
}

/// Creates the default extension-to-language mapping
/// 
/// Covers major programming languages, data formats, and configuration files.
/// Extensions are stored in lowercase for case-insensitive matching.
pub fn default_ext_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    
    // Systems programming
    map.insert("rs".to_string(), "rust".to_string());
    map.insert("c".to_string(), "c".to_string());
    map.insert("h".to_string(), "c".to_string());
    map.insert("cpp".to_string(), "cpp".to_string());
    map.insert("cxx".to_string(), "cpp".to_string());
    map.insert("cc".to_string(), "cpp".to_string());
    map.insert("hpp".to_string(), "cpp".to_string());
    map.insert("hxx".to_string(), "cpp".to_string());
    map.insert("go".to_string(), "go".to_string());
    
    // Web development
    map.insert("js".to_string(), "javascript".to_string());
    map.insert("mjs".to_string(), "javascript".to_string());
    map.insert("ts".to_string(), "typescript".to_string());
    map.insert("jsx".to_string(), "javascriptreact".to_string());
    map.insert("tsx".to_string(), "typescriptreact".to_string());
    map.insert("vue".to_string(), "vue".to_string());
    map.insert("svelte".to_string(), "svelte".to_string());
    
    // Enterprise languages
    map.insert("java".to_string(), "java".to_string());
    map.insert("kt".to_string(), "kotlin".to_string());
    map.insert("kts".to_string(), "kotlin".to_string());
    map.insert("cs".to_string(), "csharp".to_string());
    map.insert("scala".to_string(), "scala".to_string());
    map.insert("clj".to_string(), "clojure".to_string());
    map.insert("cljs".to_string(), "clojure".to_string());
    
    // Scripting languages
    map.insert("py".to_string(), "python".to_string());
    map.insert("pyi".to_string(), "python".to_string());
    map.insert("rb".to_string(), "ruby".to_string());
    map.insert("php".to_string(), "php".to_string());
    map.insert("sh".to_string(), "shell".to_string());
    map.insert("bash".to_string(), "shell".to_string());
    map.insert("zsh".to_string(), "shell".to_string());
    map.insert("fish".to_string(), "shell".to_string());
    map.insert("ps1".to_string(), "powershell".to_string());
    map.insert("psm1".to_string(), "powershell".to_string());
    
    // Data and configuration formats
    map.insert("json".to_string(), "json".to_string());
    map.insert("yaml".to_string(), "yaml".to_string());
    map.insert("yml".to_string(), "yaml".to_string());
    map.insert("toml".to_string(), "toml".to_string());
    map.insert("xml".to_string(), "xml".to_string());
    map.insert("html".to_string(), "html".to_string());
    map.insert("htm".to_string(), "html".to_string());
    map.insert("css".to_string(), "css".to_string());
    map.insert("scss".to_string(), "scss".to_string());
    map.insert("sass".to_string(), "sass".to_string());
    map.insert("less".to_string(), "less".to_string());
    
    // Documentation and markup
    map.insert("md".to_string(), "markdown".to_string());
    map.insert("markdown".to_string(), "markdown".to_string());
    map.insert("rst".to_string(), "restructuredtext".to_string());
    map.insert("tex".to_string(), "latex".to_string());
    map.insert("latex".to_string(), "latex".to_string());
    
    // Database and query languages
    map.insert("sql".to_string(), "sql".to_string());
    map.insert("psql".to_string(), "sql".to_string());
    map.insert("mysql".to_string(), "sql".to_string());
    
    // Infrastructure and deployment
    map.insert("dockerfile".to_string(), "docker".to_string());
    map.insert("containerfile".to_string(), "docker".to_string());
    map.insert("docker-compose.yml".to_string(), "docker-compose".to_string());
    map.insert("docker-compose.yaml".to_string(), "docker-compose".to_string());
    
    // Build systems and configuration
    map.insert("makefile".to_string(), "makefile".to_string());
    map.insert("cmake".to_string(), "cmake".to_string());
    map.insert("gradle".to_string(), "gradle".to_string());
    map.insert("build.gradle".to_string(), "gradle".to_string());
    map.insert("pom.xml".to_string(), "maven".to_string());
    map.insert("cargo.toml".to_string(), "cargo".to_string());
    map.insert("package.json".to_string(), "npm".to_string());
    
    map
}

/// Parse extension mapping configuration from various formats
/// 
/// Supports inline JSON (starts with '{') or file paths with extensions:
/// - .json -> JSON format
/// - .yaml/.yml -> YAML format  
/// - .toml -> TOML format
pub fn parse_ext_map_config(input: &str) -> Result<HashMap<String, String>> {
    if input.trim_start().starts_with('{') {
        // Inline JSON
        let config: HashMap<String, String> = serde_json::from_str(input)
            .context("Failed to parse inline JSON extension mapping")?;
        Ok(normalize_ext_map(config))
    } else {
        // File path - determine format by extension
        let path = Path::new(input);
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read extension mapping file: {}", input))?;
        
        let config: HashMap<String, String> = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => serde_json::from_str(&content)
                .context("Failed to parse JSON extension mapping file")?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                .context("Failed to parse YAML extension mapping file")?,
            Some("toml") => toml::from_str(&content)
                .context("Failed to parse TOML extension mapping file")?,
            _ => return Err(anyhow::anyhow!(
                "Unsupported extension mapping file format. Use .json, .yaml/.yml, or .toml"
            )),
        };
        
        Ok(normalize_ext_map(config))
    }
}

/// Normalize extension mapping to lowercase keys
fn normalize_ext_map(map: HashMap<String, String>) -> HashMap<String, String> {
    map.into_iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect()
}

/// Merge user-provided extension mappings with defaults
/// 
/// User mappings take precedence over defaults.
pub fn merge_ext_maps(
    defaults: HashMap<String, String>,
    overrides: HashMap<String, String>,
) -> HashMap<String, String> {
    let mut merged = defaults;
    merged.extend(overrides);
    merged
}

/// Main entry point for collecting source files based on scan options
pub fn collect_source_files(opts: &ScanOptions) -> Result<Vec<SourceFile>> {
    // Validate root directory
    if !opts.root.exists() {
        return Err(anyhow::anyhow!(
            "Root directory does not exist: {}", 
            opts.root.display()
        ));
    }
    
    if !opts.root.is_dir() {
        return Err(anyhow::anyhow!(
            "Root path is not a directory: {}", 
            opts.root.display()
        ));
    }
    
    // Build glob matchers for include/exclude patterns
    let include_matcher = build_glob_matcher(&opts.include)
        .context("Failed to build include pattern matcher")?;
    let exclude_matcher = build_glob_matcher(&opts.exclude)
        .context("Failed to build exclude pattern matcher")?;
    
    // Collect files using directory traversal
    let mut files = Vec::new();
    let canonical_root = opts.root.canonicalize()
        .with_context(|| format!("Failed to canonicalize root path: {}", opts.root.display()))?;
    
    // Choose traversal method based on gitignore requirements
    if opts.respect_gitignore {
        collect_with_ignore(&canonical_root, opts, &include_matcher, &exclude_matcher, &mut files)?;
    } else {
        collect_with_walkdir(&canonical_root, opts, &include_matcher, &exclude_matcher, &mut files)?;
    }
    
    // Sort by relative path for deterministic output
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    
    Ok(files)
}

/// Build a glob matcher from patterns
fn build_glob_matcher(patterns: &[String]) -> Result<globset::GlobSet> {
    if patterns.is_empty() {
        // Empty matcher matches nothing (for exclude) or everything (for include)
        return Ok(globset::GlobSetBuilder::new().build()?);
    }
    
    let mut builder = globset::GlobSetBuilder::new();
    for pattern in patterns {
        let glob = globset::Glob::new(pattern)
            .with_context(|| format!("Invalid glob pattern: {}", pattern))?;
        builder.add(glob);
    }
    
    Ok(builder.build()?)
}

/// Collect files using ignore crate (respects .gitignore)
fn collect_with_ignore(
    root: &Path,
    opts: &ScanOptions,
    include_matcher: &globset::GlobSet,
    exclude_matcher: &globset::GlobSet,
    files: &mut Vec<SourceFile>,
) -> Result<()> {
    use ignore::WalkBuilder;
    
    let walker = WalkBuilder::new(root)
        .follow_links(opts.follow_symlinks)
        .hidden(!opts.include_hidden)
        .git_ignore(opts.respect_gitignore)
        .parents(true)
        .max_depth(if opts.recursive { None } else { Some(1) })
        .build();
    
    for entry in walker {
        let entry = entry.context("Failed to read directory entry")?;
        
        // Skip directories
        if entry.file_type().map_or(false, |ft| ft.is_dir()) {
            continue;
        }
        
        // Skip non-regular files
        if !entry.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        
        let path = entry.path();
        if let Some(source_file) = process_file_entry(root, path, opts, include_matcher, exclude_matcher)? {
            files.push(source_file);
        }
    }
    
    Ok(())
}

/// Collect files using walkdir crate (basic traversal)
fn collect_with_walkdir(
    root: &Path,
    opts: &ScanOptions,
    include_matcher: &globset::GlobSet,
    exclude_matcher: &globset::GlobSet,
    files: &mut Vec<SourceFile>,
) -> Result<()> {
    use walkdir::WalkDir;
    
    let max_depth = if opts.recursive { usize::MAX } else { 1 };
    let walker = WalkDir::new(root)
        .follow_links(opts.follow_symlinks)
        .max_depth(max_depth)
        .into_iter()
        .filter_entry(|e| {
            // Filter hidden files/directories if not included
            if !opts.include_hidden {
                if let Some(name) = e.file_name().to_str() {
                    if name.starts_with('.') && name != "." && name != ".." {
                        return false;
                    }
                }
            }
            true
        });
    
    for entry in walker {
        let entry = entry.context("Failed to read directory entry")?;
        
        // Skip directories
        if entry.file_type().is_dir() {
            continue;
        }
        
        let path = entry.path();
        if let Some(source_file) = process_file_entry(root, path, opts, include_matcher, exclude_matcher)? {
            files.push(source_file);
        }
    }
    
    Ok(())
}

/// Process a single file entry and return SourceFile if it should be included
fn process_file_entry(
    root: &Path,
    path: &Path,
    opts: &ScanOptions,
    include_matcher: &globset::GlobSet,
    exclude_matcher: &globset::GlobSet,
) -> Result<Option<SourceFile>> {
    // Get relative path for glob matching
    let rel_path = path.strip_prefix(root)
        .with_context(|| format!("Failed to get relative path for: {}", path.display()))?;
    
    // Normalize path separators for consistent glob matching
    let rel_path_str = rel_path.to_string_lossy().replace('\\', "/");
    
    // Apply exclude patterns first (early exit)
    if exclude_matcher.is_match(&rel_path_str) {
        return Ok(None);
    }
    
    // Apply include patterns (if any)
    if !opts.include.is_empty() && !include_matcher.is_match(&rel_path_str) {
        return Ok(None);
    }
    
    // Get file extension and check against language map
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_lowercase())
        .unwrap_or_default();
    
    let language = match opts.ext_lang_map.get(&extension) {
        Some(lang) => lang.clone(),
        None => {
            // Skip files with unknown extensions
            return Ok(None);
        }
    };
    
    // Check file size
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for: {}", path.display()))?;
    
    let size = metadata.len();
    if let Some(max_size) = opts.max_file_size {
        if size > max_size {
            log::debug!("Skipping large file: {} ({} bytes)", path.display(), size);
            return Ok(None);
        }
    }
    
    // Create SourceFile
    Ok(Some(SourceFile {
        path: path.to_path_buf(),
        rel_path: rel_path.to_path_buf(),
        language,
        size,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[test]
    fn test_default_ext_map_coverage() {
        let map = default_ext_map();
        
        // Test major language coverage
        assert_eq!(map.get("rs"), Some(&"rust".to_string()));
        assert_eq!(map.get("js"), Some(&"javascript".to_string()));
        assert_eq!(map.get("py"), Some(&"python".to_string()));
        assert_eq!(map.get("go"), Some(&"go".to_string()));
        assert_eq!(map.get("java"), Some(&"java".to_string()));
        
        // Test data formats
        assert_eq!(map.get("json"), Some(&"json".to_string()));
        assert_eq!(map.get("yaml"), Some(&"yaml".to_string()));
        assert_eq!(map.get("toml"), Some(&"toml".to_string()));
    }
    
    #[test]
    fn test_parse_inline_json() {
        let input = r#"{"rs": "rust", "py": "python"}"#;
        let result = parse_ext_map_config(input).unwrap();
        
        assert_eq!(result.get("rs"), Some(&"rust".to_string()));
        assert_eq!(result.get("py"), Some(&"python".to_string()));
    }
    
    #[test]
    fn test_parse_json_file() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config.json");
        
        let config_content = r#"{"vue": "vue", "svelte": "svelte"}"#;
        fs::write(&config_path, config_content).unwrap();
        
        let result = parse_ext_map_config(config_path.to_str().unwrap()).unwrap();
        assert_eq!(result.get("vue"), Some(&"vue".to_string()));
        assert_eq!(result.get("svelte"), Some(&"svelte".to_string()));
    }
    
    #[test]
    fn test_merge_ext_maps() {
        let mut defaults = HashMap::new();
        defaults.insert("rs".to_string(), "rust".to_string());
        defaults.insert("js".to_string(), "javascript".to_string());
        
        let mut overrides = HashMap::new();
        overrides.insert("js".to_string(), "custom_js".to_string());
        overrides.insert("vue".to_string(), "vue".to_string());
        
        let merged = merge_ext_maps(defaults, overrides);
        
        assert_eq!(merged.get("rs"), Some(&"rust".to_string()));
        assert_eq!(merged.get("js"), Some(&"custom_js".to_string())); // Override wins
        assert_eq!(merged.get("vue"), Some(&"vue".to_string()));
    }
    
    #[test]
    fn test_normalize_ext_map() {
        let mut input = HashMap::new();
        input.insert("RS".to_string(), "rust".to_string());
        input.insert("Js".to_string(), "javascript".to_string());
        
        let normalized = normalize_ext_map(input);
        
        assert_eq!(normalized.get("rs"), Some(&"rust".to_string()));
        assert_eq!(normalized.get("js"), Some(&"javascript".to_string()));
        assert!(normalized.get("RS").is_none());
        assert!(normalized.get("Js").is_none());
    }
    
    #[test]
    fn test_scan_options_default() {
        let opts = ScanOptions::default();
        
        assert_eq!(opts.root, PathBuf::from("."));
        assert!(!opts.recursive);
        assert!(opts.include.is_empty());
        assert!(opts.exclude.is_empty());
        assert!(opts.max_file_size.is_none());
        assert!(!opts.follow_symlinks);
        assert!(!opts.include_hidden);
        assert!(opts.respect_gitignore);
        assert!(!opts.ext_lang_map.is_empty());
    }
    
    #[test]
    fn test_build_glob_matcher() {
        // Empty patterns
        let matcher = build_glob_matcher(&[]).unwrap();
        assert!(!matcher.is_match("any/path"));
        
        // Single pattern
        let patterns = vec!["**/*.rs".to_string()];
        let matcher = build_glob_matcher(&patterns).unwrap();
        assert!(matcher.is_match("src/main.rs"));
        assert!(matcher.is_match("nested/path/file.rs"));
        assert!(!matcher.is_match("file.js"));
        
        // Multiple patterns
        let patterns = vec!["**/*.rs".to_string(), "**/*.py".to_string()];
        let matcher = build_glob_matcher(&patterns).unwrap();
        assert!(matcher.is_match("file.rs"));
        assert!(matcher.is_match("file.py"));
        assert!(!matcher.is_match("file.js"));
    }
    
    #[test]
    fn test_collect_files_basic() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        
        // Create test files
        fs::write(root.join("test.rs"), "fn main() {}").unwrap();
        fs::write(root.join("script.py"), "print('hello')").unwrap();
        fs::write(root.join("README.md"), "# Test").unwrap();
        fs::write(root.join("data.txt"), "some data").unwrap(); // Unknown extension
        
        let opts = ScanOptions {
            root: root.to_path_buf(),
            recursive: false,
            ..Default::default()
        };
        
        let files = collect_source_files(&opts).unwrap();
        
        // Should find .rs, .py, .md files but not .txt (unknown extension)
        assert_eq!(files.len(), 3);
        
        let file_names: Vec<&str> = files.iter()
            .map(|f| f.rel_path.file_name().unwrap().to_str().unwrap())
            .collect();
        
        assert!(file_names.contains(&"test.rs"));
        assert!(file_names.contains(&"script.py"));
        assert!(file_names.contains(&"README.md"));
        assert!(!file_names.contains(&"data.txt"));
    }
    
    #[test]
    fn test_collect_files_recursive() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        
        // Create nested directory structure
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn hello() {}").unwrap();
        fs::write(root.join("tests/test.rs"), "#[test] fn test() {}").unwrap();
        
        // Non-recursive should only find root level files
        let opts_shallow = ScanOptions {
            root: root.to_path_buf(),
            recursive: false,
            ..Default::default()
        };
        
        let files_shallow = collect_source_files(&opts_shallow).unwrap();
        assert_eq!(files_shallow.len(), 1);
        assert_eq!(files_shallow[0].rel_path, PathBuf::from("main.rs"));
        
        // Recursive should find all files
        let opts_deep = ScanOptions {
            root: root.to_path_buf(),
            recursive: true,
            ..Default::default()
        };
        
        let files_deep = collect_source_files(&opts_deep).unwrap();
        assert_eq!(files_deep.len(), 3);
        
        let rel_paths: Vec<&Path> = files_deep.iter().map(|f| f.rel_path.as_path()).collect();
        assert!(rel_paths.contains(&Path::new("main.rs")));
        assert!(rel_paths.contains(&Path::new("src/lib.rs")));
        assert!(rel_paths.contains(&Path::new("tests/test.rs")));
    }
    
    #[test]
    fn test_include_exclude_patterns() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();
        
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn hello() {}").unwrap();
        fs::write(root.join("target/debug.rs"), "// build artifact").unwrap();
        fs::write(root.join("tests/test.rs"), "#[test] fn test() {}").unwrap();
        
        // Test include pattern
        let opts_include = ScanOptions {
            root: root.to_path_buf(),
            recursive: true,
            include: vec!["src/**/*.rs".to_string()],
            ..Default::default()
        };
        
        let files_include = collect_source_files(&opts_include).unwrap();
        assert_eq!(files_include.len(), 2);
        
        let rel_paths: Vec<&Path> = files_include.iter().map(|f| f.rel_path.as_path()).collect();
        assert!(rel_paths.contains(&Path::new("src/main.rs")));
        assert!(rel_paths.contains(&Path::new("src/lib.rs")));
        
        // Test exclude pattern
        let opts_exclude = ScanOptions {
            root: root.to_path_buf(),
            recursive: true,
            exclude: vec!["target/**".to_string()],
            ..Default::default()
        };
        
        let files_exclude = collect_source_files(&opts_exclude).unwrap();
        assert_eq!(files_exclude.len(), 3); // All except target/debug.rs
        
        let rel_paths: Vec<&Path> = files_exclude.iter().map(|f| f.rel_path.as_path()).collect();
        assert!(!rel_paths.contains(&Path::new("target/debug.rs")));
    }
    
    #[test]
    fn test_max_file_size() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        
        fs::write(root.join("small.rs"), "fn main() {}").unwrap(); // ~12 bytes
        fs::write(root.join("large.rs"), "fn main() {}\n".repeat(1000)).unwrap(); // ~13KB
        
        let opts = ScanOptions {
            root: root.to_path_buf(),
            max_file_size: Some(1000), // 1KB limit
            ..Default::default()
        };
        
        let files = collect_source_files(&opts).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, PathBuf::from("small.rs"));
    }
    
    #[test]
    fn test_custom_language_mapping() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        
        fs::write(root.join("file.custom"), "custom content").unwrap();
        fs::write(root.join("file.rs"), "fn main() {}").unwrap();
        
        let mut custom_map = default_ext_map();
        custom_map.insert("custom".to_string(), "custom_lang".to_string());
        
        let opts = ScanOptions {
            root: root.to_path_buf(),
            ext_lang_map: custom_map,
            ..Default::default()
        };
        
        let files = collect_source_files(&opts).unwrap();
        assert_eq!(files.len(), 2);
        
        let custom_file = files.iter().find(|f| f.rel_path.file_name().unwrap() == "file.custom").unwrap();
        assert_eq!(custom_file.language, "custom_lang");
        
        let rust_file = files.iter().find(|f| f.rel_path.file_name().unwrap() == "file.rs").unwrap();
        assert_eq!(rust_file.language, "rust");
    }
}