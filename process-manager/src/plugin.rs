//! Configuration plugin system for process enhancement

use crate::{error::PluginError, ProcessConfig};

/// Trait for configuration plugins that can enhance process configurations
pub trait ConfigurationPlugin: Send + Sync {
    /// Get the name of this plugin
    fn name(&self) -> &str;

    /// Check if this plugin is applicable to the given configuration
    fn is_applicable(&self, config: &ProcessConfig) -> bool;

    /// Enhance the given configuration
    fn enhance_config(&self, config: ProcessConfig) -> Result<ProcessConfig, PluginError>;

    /// Get the priority of this plugin (lower numbers = higher priority)
    fn priority(&self) -> u32;
}

/// Registry for managing configuration plugins
pub struct PluginRegistry {
    plugins: Vec<Box<dyn ConfigurationPlugin>>,
}

impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Register a new plugin
    pub fn register(&mut self, plugin: Box<dyn ConfigurationPlugin>) {
        self.plugins.push(plugin);
        // Sort by priority (lower numbers first)
        self.plugins.sort_by_key(|p| p.priority());
    }

    /// Apply all applicable plugins to the given configuration
    pub fn apply_plugins(&self, config: ProcessConfig) -> ProcessConfig {
        let mut enhanced_config = config;

        for plugin in &self.plugins {
            if plugin.is_applicable(&enhanced_config) {
                match plugin.enhance_config(enhanced_config.clone()) {
                    Ok(new_config) => {
                        tracing::debug!("Configuration enhanced by plugin '{}'", plugin.name());
                        enhanced_config = new_config;
                    }
                    Err(error) => {
                        tracing::warn!("Plugin '{}' failed: {}", plugin.name(), error);
                        // Continue with original config
                    }
                }
            }
        }

        enhanced_config
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
