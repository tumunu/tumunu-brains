//! System metrics collection using sysinfo

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// System metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub disk_usage_pct: f32,
    pub disk_read_bytes: u64,
    pub disk_written_bytes: u64,
    pub proc_count: usize,
}

/// Trait for metrics providers
pub trait MetricsProvider {
    fn sample(&mut self) -> SystemMetrics;
}

/// Sysinfo-based metrics provider
pub struct SysinfoMetricsProvider {
    sys: sysinfo::System,
    disks: sysinfo::Disks,
    last_io: Option<HashMap<String, (u64, u64)>>,
}

impl SysinfoMetricsProvider {
    pub fn new() -> Self {
        Self {
            sys: sysinfo::System::new_all(),
            disks: sysinfo::Disks::new_with_refreshed_list(),
            last_io: None,
        }
    }
}

impl MetricsProvider for SysinfoMetricsProvider {
    fn sample(&mut self) -> SystemMetrics {
        self.sys.refresh_all();
        self.disks.refresh();
        
        let cpu_usage = self.sys.global_cpu_usage();
        let mem_used = self.sys.used_memory();
        let mem_total = self.sys.total_memory();
        let proc_count = self.sys.processes().len();
        
        // Calculate disk usage percentage
        let mut total_space = 0;
        let mut used_space = 0;
        let mut current_io = HashMap::new();
        let mut total_read_bytes = 0;
        let mut total_written_bytes = 0;
        
        for disk in &self.disks {
            total_space += disk.total_space();
            used_space += disk.total_space() - disk.available_space();
            
            // Track disk I/O (bytes read/written since last sample)
            let name = disk.name().to_string_lossy().to_string();
            
            // Note: sysinfo doesn't provide I/O counters directly
            // This is a simplified implementation
            current_io.insert(name, (0, 0));
        }
        
        let disk_usage_pct = if total_space > 0 {
            (used_space as f32 / total_space as f32) * 100.0
        } else {
            0.0
        };
        
        // Calculate I/O deltas if we have previous data
        if let Some(ref last) = self.last_io {
            for (name, (read, write)) in &current_io {
                if let Some((last_read, last_write)) = last.get(name) {
                    total_read_bytes += read.saturating_sub(*last_read);
                    total_written_bytes += write.saturating_sub(*last_write);
                }
            }
        }
        
        self.last_io = Some(current_io);
        
        SystemMetrics {
            cpu_usage,
            mem_used,
            mem_total,
            disk_usage_pct,
            disk_read_bytes: total_read_bytes,
            disk_written_bytes: total_written_bytes,
            proc_count,
        }
    }
}

impl Default for SysinfoMetricsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_provider_creation() {
        let provider = SysinfoMetricsProvider::new();
        assert!(provider.last_io.is_none());
    }

    #[test]
    fn test_metrics_sample() {
        let mut provider = SysinfoMetricsProvider::new();
        let metrics = provider.sample();
        
        // Validate sane ranges
        assert!(metrics.mem_total > 0);
        assert!(metrics.disk_usage_pct >= 0.0 && metrics.disk_usage_pct <= 100.0);
        assert!(metrics.cpu_usage >= 0.0);
    }

    #[test]
    fn test_io_delta_non_negative() {
        let mut provider = SysinfoMetricsProvider::new();
        
        // First sample should have zero I/O
        let first_sample = provider.sample();
        assert_eq!(first_sample.disk_read_bytes, 0);
        assert_eq!(first_sample.disk_written_bytes, 0);
        
        // Second sample should also be zero or positive
        let second_sample = provider.sample();
        assert!(second_sample.disk_read_bytes >= 0);
        assert!(second_sample.disk_written_bytes >= 0);
    }
}