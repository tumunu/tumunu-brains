//! Plugin registry for managing detection engines and analysis modules

use crate::plugin::{Plugin, PluginMetadata};
use brains_detection::PatternEngine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Plugin registry for managing loaded plugins
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginRegistry {
    plugins: HashMap<String, Plugin>,
    plugin_directory: PathBuf,
    metadata_cache: HashMap<String, PluginMetadata>,
    #[serde(skip)]
    active_engines: HashMap<String, Arc<dyn PatternEngine + Send + Sync>>,
}

impl PluginRegistry {
    /// Create new plugin registry
    pub fn new(plugin_directory: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&plugin_directory)?;
        
        Ok(Self {
            plugins: HashMap::new(),
            plugin_directory,
            metadata_cache: HashMap::new(),
            active_engines: HashMap::new(),
        })
    }
    
    /// Load plugin from file
    pub fn load_plugin(&mut self, plugin_path: PathBuf) -> anyhow::Result<Plugin> {
        let metadata = self.load_plugin_metadata(&plugin_path)?;
        
        // Create plugin instance
        let plugin = Plugin {
            metadata,
            library_path: plugin_path,
            loaded: false,
        };
        
        Ok(plugin)
    }
    
    /// Register plugin in registry
    pub fn register_plugin(&mut self, plugin: Plugin) -> anyhow::Result<()> {
        let plugin_name = plugin.metadata.name.clone();
        
        // Check for conflicts
        if self.plugins.contains_key(&plugin_name) {
            return Err(anyhow::anyhow!("Plugin already registered: {}", plugin_name));
        }
        
        // Cache metadata
        self.metadata_cache.insert(plugin_name.clone(), plugin.metadata.clone());
        
        // Register plugin
        self.plugins.insert(plugin_name, plugin);
        
        Ok(())
    }
    
    /// Unregister plugin
    pub fn unregister_plugin(&mut self, plugin_name: &str) -> anyhow::Result<()> {
        if !self.plugins.contains_key(plugin_name) {
            return Err(anyhow::anyhow!("Plugin not found: {}", plugin_name));
        }
        
        self.plugins.remove(plugin_name);
        self.metadata_cache.remove(plugin_name);
        
        Ok(())
    }
    
    /// Get plugin by name
    pub fn get_plugin(&self, plugin_name: &str) -> Option<&Plugin> {
        self.plugins.get(plugin_name)
    }
    
    /// List all registered plugins
    pub fn list_plugins(&self) -> Vec<&PluginMetadata> {
        self.metadata_cache.values().collect()
    }
    
    /// Register pattern engine
    pub fn register_engine(&mut self, engine: Arc<dyn PatternEngine + Send + Sync>) -> anyhow::Result<()> {
        let id = engine.id().to_string();
        
        if self.active_engines.contains_key(&id) {
            return Err(anyhow::anyhow!("Engine already registered: {}", id));
        }
        
        self.active_engines.insert(id, engine);
        Ok(())
    }
    
    /// Get pattern engine by ID
    pub fn get_engine(&self, id: &str) -> Option<Arc<dyn PatternEngine + Send + Sync>> {
        self.active_engines.get(id).cloned()
    }
    
    /// List all active engine IDs
    pub fn list_engines(&self) -> Vec<String> {
        self.active_engines.keys().cloned().collect()
    }
    
    /// Unregister pattern engine
    pub fn unregister_engine(&mut self, id: &str) -> anyhow::Result<()> {
        if !self.active_engines.contains_key(id) {
            return Err(anyhow::anyhow!("Engine not found: {}", id));
        }
        
        self.active_engines.remove(id);
        Ok(())
    }
    
    /// Scan plugin directory for available plugins
    pub fn scan_plugins(&mut self) -> anyhow::Result<Vec<PathBuf>> {
        let mut plugin_paths = Vec::new();
        
        if !self.plugin_directory.exists() {
            return Ok(plugin_paths);
        }
        
        for entry in std::fs::read_dir(&self.plugin_directory)? {
            let entry = entry?;
            let path = entry.path();
            
            // Look for shared library files
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "so" || extension == "dll" || extension == "dylib" {
                        plugin_paths.push(path);
                    }
                }
            }
        }
        
        Ok(plugin_paths)
    }
    
    /// Load plugin metadata
    fn load_plugin_metadata(&self, plugin_path: &Path) -> anyhow::Result<PluginMetadata> {
        // Look for metadata file alongside plugin
        let metadata_path = plugin_path.with_extension("json");
        
        if metadata_path.exists() {
            let metadata_content = std::fs::read_to_string(metadata_path)?;
            let metadata: PluginMetadata = serde_json::from_str(&metadata_content)?;
            Ok(metadata)
        } else {
            // Generate default metadata if none exists
            let plugin_name = plugin_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            
            Ok(PluginMetadata::default_for_name(plugin_name))
        }
    }
}

impl Clone for PluginRegistry {
    fn clone(&self) -> Self {
        Self {
            plugins: self.plugins.clone(),
            plugin_directory: self.plugin_directory.clone(),
            metadata_cache: self.metadata_cache.clone(),
            active_engines: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_registry_creation() {
        let temp_dir = TempDir::new().unwrap();
        let registry = PluginRegistry::new(temp_dir.path().to_path_buf()).unwrap();
        
        assert_eq!(registry.plugins.len(), 0);
        assert!(registry.plugin_directory.exists());
    }
    
    #[test]
    fn test_plugin_registration() {
        let temp_dir = TempDir::new().unwrap();
        let mut registry = PluginRegistry::new(temp_dir.path().to_path_buf()).unwrap();
        
        let plugin = Plugin {
            metadata: PluginMetadata::default_for_name("test_plugin".to_string()),
            library_path: temp_dir.path().join("test_plugin.so"),
            loaded: false,
        };
        
        registry.register_plugin(plugin).unwrap();
        
        assert_eq!(registry.plugins.len(), 1);
        assert!(registry.get_plugin("test_plugin").is_some());
    }
    
    #[test]
    fn test_plugin_unregistration() {
        let temp_dir = TempDir::new().unwrap();
        let mut registry = PluginRegistry::new(temp_dir.path().to_path_buf()).unwrap();
        
        let plugin = Plugin {
            metadata: PluginMetadata::default_for_name("test_plugin".to_string()),
            library_path: temp_dir.path().join("test_plugin.so"),
            loaded: false,
        };
        
        registry.register_plugin(plugin).unwrap();
        assert_eq!(registry.plugins.len(), 1);
        
        registry.unregister_plugin("test_plugin").unwrap();
        assert_eq!(registry.plugins.len(), 0);
        assert!(registry.get_plugin("test_plugin").is_none());
    }
}