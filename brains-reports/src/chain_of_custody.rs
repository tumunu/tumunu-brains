//! Chain of custody tracking for forensic evidence

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Chain of custody tracking for forensic evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub custody_id: Uuid,
    pub evidence_id: Uuid,
    pub custody_entries: Vec<CustodyEntry>,
    pub integrity_checks: Vec<IntegrityCheck>,
    pub access_log: Vec<AccessEntry>,
    pub storage_locations: Vec<StorageLocation>,
    pub transfer_records: Vec<TransferRecord>,
}

/// Individual custody entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub entry_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub custodian: String,
    pub action: CustodyAction,
    pub location: String,
    pub purpose: String,
    pub notes: String,
    pub witness: Option<String>,
    pub signature: Option<String>,
}

/// Custody actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CustodyAction {
    Created,
    Acquired,
    Accessed,
    Analyzed,
    Copied,
    Transferred,
    Sealed,
    Unsealed,
    Archived,
    Destroyed,
    Returned,
}

/// Integrity check record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityCheck {
    pub check_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub checker: String,
    pub method: String,
    pub hash_before: String,
    pub hash_after: String,
    pub integrity_maintained: bool,
    pub notes: String,
}

/// Access entry for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEntry {
    pub access_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub accessor: String,
    pub access_type: AccessType,
    pub purpose: String,
    pub duration: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub authorization: String,
}

/// Access types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessType {
    Read,
    Write,
    Execute,
    Copy,
    Export,
    Delete,
    Metadata,
}

/// Storage location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLocation {
    pub location_id: Uuid,
    pub location_type: String,
    pub address: String,
    pub access_controls: Vec<String>,
    pub security_level: String,
    pub environmental_controls: Vec<String>,
    pub backup_locations: Vec<String>,
    pub responsible_party: String,
}

/// Transfer record between custodians
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub transfer_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub from_custodian: String,
    pub to_custodian: String,
    pub transfer_method: String,
    pub reason: String,
    pub authorization: String,
    pub witness: Option<String>,
    pub condition_before: String,
    pub condition_after: String,
    pub transport_security: Vec<String>,
}

impl ChainOfCustody {
    /// Create new chain of custody
    pub fn new(evidence_id: Uuid) -> Self {
        Self {
            custody_id: Uuid::new_v4(),
            evidence_id,
            custody_entries: Vec::new(),
            integrity_checks: Vec::new(),
            access_log: Vec::new(),
            storage_locations: Vec::new(),
            transfer_records: Vec::new(),
        }
    }
    
    /// Add custody entry
    pub fn add_custody_entry(
        &mut self,
        custodian: String,
        action: CustodyAction,
        location: String,
        purpose: String,
        notes: String,
    ) {
        let entry = CustodyEntry {
            entry_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            custodian,
            action,
            location,
            purpose,
            notes,
            witness: None,
            signature: None,
        };
        
        self.custody_entries.push(entry);
    }
    
    /// Add integrity check
    pub fn add_integrity_check(
        &mut self,
        checker: String,
        method: String,
        hash_before: String,
        hash_after: String,
        notes: String,
    ) {
        let check = IntegrityCheck {
            check_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            checker,
            method,
            hash_before: hash_before.clone(),
            hash_after: hash_after.clone(),
            integrity_maintained: hash_before == hash_after,
            notes,
        };
        
        self.integrity_checks.push(check);
    }
    
    /// Add access entry
    pub fn add_access_entry(
        &mut self,
        accessor: String,
        access_type: AccessType,
        purpose: String,
        authorization: String,
    ) {
        let entry = AccessEntry {
            access_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            accessor,
            access_type,
            purpose,
            duration: None,
            ip_address: None,
            user_agent: None,
            authorization,
        };
        
        self.access_log.push(entry);
    }
    
    /// Add transfer record
    pub fn add_transfer(
        &mut self,
        from_custodian: String,
        to_custodian: String,
        transfer_method: String,
        reason: String,
        authorization: String,
        condition_before: String,
        condition_after: String,
    ) {
        let transfer = TransferRecord {
            transfer_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            from_custodian,
            to_custodian,
            transfer_method,
            reason,
            authorization,
            witness: None,
            condition_before,
            condition_after,
            transport_security: Vec::new(),
        };
        
        self.transfer_records.push(transfer);
    }
    
    /// Get current custodian
    pub fn get_current_custodian(&self) -> Option<&str> {
        self.custody_entries
            .last()
            .map(|entry| entry.custodian.as_str())
    }
    
    /// Get custody timeline
    pub fn get_timeline(&self) -> Vec<&CustodyEntry> {
        let mut entries = self.custody_entries.iter().collect::<Vec<_>>();
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        entries
    }
    
    /// Validate chain continuity
    pub fn validate_continuity(&self) -> Result<bool, String> {
        if self.custody_entries.is_empty() {
            return Err("No custody entries found".to_string());
        }
        
        // Check for gaps in custody
        let mut previous_custodian: Option<&str> = None;
        
        for entry in self.get_timeline() {
            match entry.action {
                CustodyAction::Created => {
                    if previous_custodian.is_some() {
                        return Err("Multiple creation entries found".to_string());
                    }
                    previous_custodian = Some(&entry.custodian);
                }
                CustodyAction::Transferred => {
                    if previous_custodian.is_none() {
                        return Err("Transfer without prior custody".to_string());
                    }
                    previous_custodian = Some(&entry.custodian);
                }
                _ => {
                    if previous_custodian.is_none() {
                        return Err("Action without established custody".to_string());
                    }
                }
            }
        }
        
        Ok(true)
    }
    
    /// Get custody statistics
    pub fn get_statistics(&self) -> CustodyStatistics {
        let total_entries = self.custody_entries.len();
        let total_transfers = self.transfer_records.len();
        let total_accesses = self.access_log.len();
        let total_integrity_checks = self.integrity_checks.len();
        
        let integrity_violations = self.integrity_checks
            .iter()
            .filter(|check| !check.integrity_maintained)
            .count();
        
        let unique_custodians = self.custody_entries
            .iter()
            .map(|entry| entry.custodian.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        
        CustodyStatistics {
            total_entries,
            total_transfers,
            total_accesses,
            total_integrity_checks,
            integrity_violations,
            unique_custodians,
            chain_duration: self.get_chain_duration(),
        }
    }
    
    /// Get chain duration
    fn get_chain_duration(&self) -> Option<chrono::Duration> {
        if let (Some(first), Some(last)) = (self.custody_entries.first(), self.custody_entries.last()) {
            Some(last.timestamp - first.timestamp)
        } else {
            None
        }
    }
}

/// Custody statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyStatistics {
    pub total_entries: usize,
    pub total_transfers: usize,
    pub total_accesses: usize,
    pub total_integrity_checks: usize,
    pub integrity_violations: usize,
    pub unique_custodians: usize,
    pub chain_duration: Option<chrono::Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_of_custody_creation() {
        let evidence_id = Uuid::new_v4();
        let chain = ChainOfCustody::new(evidence_id);
        
        assert_eq!(chain.evidence_id, evidence_id);
        assert_eq!(chain.custody_entries.len(), 0);
    }
    
    #[test]
    fn test_custody_entry_addition() {
        let evidence_id = Uuid::new_v4();
        let mut chain = ChainOfCustody::new(evidence_id);
        
        chain.add_custody_entry(
            "John Doe".to_string(),
            CustodyAction::Created,
            "Lab A".to_string(),
            "Evidence collection".to_string(),
            "Initial collection from scene".to_string(),
        );
        
        assert_eq!(chain.custody_entries.len(), 1);
        assert_eq!(chain.get_current_custodian(), Some("John Doe"));
    }
    
    #[test]
    fn test_integrity_check() {
        let evidence_id = Uuid::new_v4();
        let mut chain = ChainOfCustody::new(evidence_id);
        
        let hash = "abcd1234";
        chain.add_integrity_check(
            "Jane Smith".to_string(),
            "SHA256".to_string(),
            hash.to_string(),
            hash.to_string(),
            "Routine integrity check".to_string(),
        );
        
        assert_eq!(chain.integrity_checks.len(), 1);
        assert!(chain.integrity_checks[0].integrity_maintained);
    }
    
    #[test]
    fn test_custody_continuity_validation() {
        let evidence_id = Uuid::new_v4();
        let mut chain = ChainOfCustody::new(evidence_id);
        
        // Add initial custody
        chain.add_custody_entry(
            "John Doe".to_string(),
            CustodyAction::Created,
            "Lab A".to_string(),
            "Evidence collection".to_string(),
            "Initial collection".to_string(),
        );
        
        // Add transfer
        chain.add_custody_entry(
            "Jane Smith".to_string(),
            CustodyAction::Transferred,
            "Lab B".to_string(),
            "Analysis".to_string(),
            "Transferred for analysis".to_string(),
        );
        
        assert!(chain.validate_continuity().is_ok());
    }
}
