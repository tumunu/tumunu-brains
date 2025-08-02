//! Plugin governance and approval system

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Plugin governance system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginGovernance {
    approval_policies: HashMap<String, ApprovalPolicy>,
    approved_plugins: HashMap<String, ApprovalRecord>,
    review_queue: Vec<ReviewRequest>,
    reviewers: HashMap<String, Reviewer>,
}

/// Approval policy for plugin categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    pub category: String,
    pub required_approvals: usize,
    pub approval_criteria: Vec<ApprovalCriterion>,
    pub required_reviewers: Vec<String>,
    pub security_requirements: Vec<String>,
    pub testing_requirements: Vec<String>,
    pub documentation_requirements: Vec<String>,
}

/// Approval criterion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalCriterion {
    pub criterion_type: String,
    pub description: String,
    pub required: bool,
    pub weight: f64,
}

/// Approval record for plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub plugin_name: String,
    pub plugin_version: String,
    pub approval_status: ApprovalStatus,
    pub approval_date: chrono::DateTime<chrono::Utc>,
    pub expiry_date: Option<chrono::DateTime<chrono::Utc>>,
    pub approved_by: Vec<String>,
    pub conditions: Vec<String>,
    pub review_notes: String,
}

/// Approval status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    UnderReview,
    Approved,
    ConditionallyApproved,
    Rejected,
    Suspended,
    Revoked,
    Expired,
}

/// Review request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRequest {
    pub request_id: Uuid,
    pub plugin_name: String,
    pub plugin_version: String,
    pub requested_by: String,
    pub request_date: chrono::DateTime<chrono::Utc>,
    pub priority: ReviewPriority,
    pub review_type: ReviewType,
    pub status: ReviewStatus,
    pub assigned_reviewers: Vec<String>,
    pub deadline: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata: HashMap<String, String>,
}

/// Review priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReviewPriority {
    Low,
    Normal,
    High,
    Critical,
    Emergency,
}

/// Review type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewType {
    Initial,
    Update,
    Security,
    Compliance,
    Emergency,
}

/// Review status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewStatus {
    Submitted,
    Assigned,
    InProgress,
    Completed,
    Cancelled,
}

/// Reviewer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reviewer {
    pub reviewer_id: String,
    pub name: String,
    pub email: String,
    pub specializations: Vec<String>,
    pub security_clearance: SecurityClearance,
    pub active: bool,
    pub workload: usize,
    pub availability: ReviewerAvailability,
}

/// Security clearance levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityClearance {
    None,
    Basic,
    Restricted,
    Confidential,
    Secret,
    TopSecret,
}

/// Reviewer availability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewerAvailability {
    pub available: bool,
    pub available_until: Option<chrono::DateTime<chrono::Utc>>,
    pub max_concurrent_reviews: usize,
    pub estimated_response_time_hours: u64,
}

impl PluginGovernance {
    /// Create new governance system
    pub fn new() -> Self {
        Self {
            approval_policies: Self::default_policies(),
            approved_plugins: HashMap::new(),
            review_queue: Vec::new(),
            reviewers: HashMap::new(),
        }
    }
    
    /// Check if plugin is approved
    pub fn is_approved(&self, plugin_name: &str) -> bool {
        if let Some(record) = self.approved_plugins.get(plugin_name) {
            match record.approval_status {
                ApprovalStatus::Approved | ApprovalStatus::ConditionallyApproved => {
                    // Check if not expired
                    if let Some(expiry) = record.expiry_date {
                        chrono::Utc::now() < expiry
                    } else {
                        true
                    }
                }
                _ => false,
            }
        } else {
            false
        }
    }
    
    /// Submit plugin for review
    pub fn submit_for_review(&mut self, plugin_name: String, plugin_version: String, requested_by: String) -> anyhow::Result<Uuid> {
        let request_id = Uuid::new_v4();
        
        let request = ReviewRequest {
            request_id,
            plugin_name: plugin_name.clone(),
            plugin_version,
            requested_by,
            request_date: chrono::Utc::now(),
            priority: ReviewPriority::Normal,
            review_type: ReviewType::Initial,
            status: ReviewStatus::Submitted,
            assigned_reviewers: Vec::new(),
            deadline: None,
            metadata: HashMap::new(),
        };
        
        // Auto-assign reviewers
        let mut request = request;
        self.assign_reviewers(&mut request)?;
        
        self.review_queue.push(request);
        
        Ok(request_id)
    }
    
    /// Assign reviewers to request
    pub fn assign_reviewers(&self, request: &mut ReviewRequest) -> anyhow::Result<()> {
        // Determine required reviewers based on plugin category
        let policy = self.get_policy_for_plugin(&request.plugin_name)?;
        
        let mut assigned_reviewers = Vec::new();
        
        // Find available reviewers with appropriate clearance
        for reviewer_id in &policy.required_reviewers {
            if let Some(reviewer) = self.reviewers.get(reviewer_id) {
                if reviewer.active && reviewer.availability.available {
                    assigned_reviewers.push(reviewer_id.clone());
                    if assigned_reviewers.len() >= policy.required_approvals {
                        break;
                    }
                }
            }
        }
        
        // Fallback to default reviewer if none available
        if assigned_reviewers.is_empty() {
            assigned_reviewers.push("security-bot".to_string());
        }
        
        // Assign reviewers to the request
        request.assigned_reviewers = assigned_reviewers;
        request.status = ReviewStatus::Assigned;
        
        Ok(())
    }
    
    /// Get policy for plugin
    fn get_policy_for_plugin(&self, plugin_name: &str) -> anyhow::Result<&ApprovalPolicy> {
        // For now, use default policy
        // In practice, would determine based on plugin metadata
        self.approval_policies.get("default")
            .ok_or_else(|| anyhow::anyhow!("No policy found for plugin: {}", plugin_name))
    }
    
    /// Approve plugin
    pub fn approve_plugin(&mut self, plugin_name: String, plugin_version: String, approved_by: Vec<String>) -> anyhow::Result<()> {
        let record = ApprovalRecord {
            plugin_name: plugin_name.clone(),
            plugin_version,
            approval_status: ApprovalStatus::Approved,
            approval_date: chrono::Utc::now(),
            expiry_date: Some(chrono::Utc::now() + chrono::Duration::days(365)), // 1 year expiry
            approved_by,
            conditions: Vec::new(),
            review_notes: String::new(),
        };
        
        self.approved_plugins.insert(plugin_name, record);
        
        Ok(())
    }
    
    /// Reject plugin
    pub fn reject_plugin(&mut self, plugin_name: String, plugin_version: String, reason: String) -> anyhow::Result<()> {
        let record = ApprovalRecord {
            plugin_name: plugin_name.clone(),
            plugin_version,
            approval_status: ApprovalStatus::Rejected,
            approval_date: chrono::Utc::now(),
            expiry_date: None,
            approved_by: Vec::new(),
            conditions: Vec::new(),
            review_notes: reason,
        };
        
        self.approved_plugins.insert(plugin_name, record);
        
        Ok(())
    }
    
    /// Add reviewer
    pub fn add_reviewer(&mut self, reviewer: Reviewer) {
        self.reviewers.insert(reviewer.reviewer_id.clone(), reviewer);
    }
    
    /// Get pending reviews
    pub fn get_pending_reviews(&self) -> Vec<&ReviewRequest> {
        self.review_queue.iter()
            .filter(|r| matches!(r.status, ReviewStatus::Submitted | ReviewStatus::Assigned | ReviewStatus::InProgress))
            .collect()
    }
    
    /// Get approval status
    pub fn get_approval_status(&self, plugin_name: &str) -> ApprovalStatus {
        self.approved_plugins.get(plugin_name)
            .map(|record| record.approval_status.clone())
            .unwrap_or(ApprovalStatus::Pending)
    }
    
    /// Create default approval policies
    fn default_policies() -> HashMap<String, ApprovalPolicy> {
        let mut policies = HashMap::new();
        
        // Default policy for experimental plugins
        policies.insert("default".to_string(), ApprovalPolicy {
            category: "experimental".to_string(),
            required_approvals: 1,
            approval_criteria: vec![
                ApprovalCriterion {
                    criterion_type: "code_quality".to_string(),
                    description: "Code meets quality standards".to_string(),
                    required: true,
                    weight: 1.0,
                },
                ApprovalCriterion {
                    criterion_type: "security_review".to_string(),
                    description: "Security review completed".to_string(),
                    required: true,
                    weight: 1.0,
                },
            ],
            required_reviewers: vec!["admin".to_string()],
            security_requirements: vec!["sandbox_required".to_string()],
            testing_requirements: vec!["unit_tests".to_string()],
            documentation_requirements: vec!["readme".to_string()],
        });
        
        // Policy for surveillance pattern plugins
        policies.insert("surveillance".to_string(), ApprovalPolicy {
            category: "surveillance".to_string(),
            required_approvals: 2,
            approval_criteria: vec![
                ApprovalCriterion {
                    criterion_type: "ethics_review".to_string(),
                    description: "Ethics committee approval".to_string(),
                    required: true,
                    weight: 1.0,
                },
                ApprovalCriterion {
                    criterion_type: "legal_review".to_string(),
                    description: "Legal compliance review".to_string(),
                    required: true,
                    weight: 1.0,
                },
                ApprovalCriterion {
                    criterion_type: "security_audit".to_string(),
                    description: "Comprehensive security audit".to_string(),
                    required: true,
                    weight: 1.0,
                },
            ],
            required_reviewers: vec!["ethics_committee".to_string(), "legal_review".to_string()],
            security_requirements: vec!["encrypted_storage".to_string(), "audit_logging".to_string()],
            testing_requirements: vec!["integration_tests".to_string(), "security_tests".to_string()],
            documentation_requirements: vec!["ethical_impact_assessment".to_string()],
        });
        
        // Policy for classified plugins
        policies.insert("classified".to_string(), ApprovalPolicy {
            category: "classified".to_string(),
            required_approvals: 3,
            approval_criteria: vec![
                ApprovalCriterion {
                    criterion_type: "security_clearance".to_string(),
                    description: "All reviewers must have appropriate clearance".to_string(),
                    required: true,
                    weight: 1.0,
                },
                ApprovalCriterion {
                    criterion_type: "compartmentalization".to_string(),
                    description: "Proper information compartmentalization".to_string(),
                    required: true,
                    weight: 1.0,
                },
            ],
            required_reviewers: vec!["security_officer".to_string(), "classification_authority".to_string()],
            security_requirements: vec!["top_secret_handling".to_string()],
            testing_requirements: vec!["classified_test_environment".to_string()],
            documentation_requirements: vec!["classification_guide".to_string()],
        });
        
        policies
    }
}

impl Default for PluginGovernance {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_creation() {
        let governance = PluginGovernance::new();
        assert_eq!(governance.approved_plugins.len(), 0);
        assert_eq!(governance.review_queue.len(), 0);
        assert!(governance.approval_policies.len() > 0);
    }
    
    #[test]
    fn test_plugin_approval() {
        let mut governance = PluginGovernance::new();
        
        // Plugin not approved initially
        assert!(!governance.is_approved("test_plugin"));
        
        // Approve plugin
        governance.approve_plugin(
            "test_plugin".to_string(),
            "1.0.0".to_string(),
            vec!["admin".to_string()],
        ).unwrap();
        
        // Plugin should now be approved
        assert!(governance.is_approved("test_plugin"));
        assert_eq!(governance.get_approval_status("test_plugin"), ApprovalStatus::Approved);
    }
    
    #[test]
    fn test_plugin_rejection() {
        let mut governance = PluginGovernance::new();
        
        governance.reject_plugin(
            "test_plugin".to_string(),
            "1.0.0".to_string(),
            "Security concerns".to_string(),
        ).unwrap();
        
        assert!(!governance.is_approved("test_plugin"));
        assert_eq!(governance.get_approval_status("test_plugin"), ApprovalStatus::Rejected);
    }
    
    #[test]
    fn test_review_submission() {
        let mut governance = PluginGovernance::new();
        
        // Add a reviewer
        let reviewer = Reviewer {
            reviewer_id: "admin".to_string(),
            name: "Admin User".to_string(),
            email: "admin@example.com".to_string(),
            specializations: vec!["security".to_string()],
            security_clearance: SecurityClearance::Basic,
            active: true,
            workload: 0,
            availability: ReviewerAvailability {
                available: true,
                available_until: None,
                max_concurrent_reviews: 5,
                estimated_response_time_hours: 24,
            },
        };
        governance.add_reviewer(reviewer);
        
        let request_id = governance.submit_for_review(
            "test_plugin".to_string(),
            "1.0.0".to_string(),
            "developer".to_string(),
        ).unwrap();
        
        assert_eq!(governance.review_queue.len(), 1);
        assert_eq!(governance.review_queue[0].request_id, request_id);
    }
    
    #[test]
    fn test_security_clearance_ordering() {
        assert!(SecurityClearance::None < SecurityClearance::Basic);
        assert!(SecurityClearance::Basic < SecurityClearance::Restricted);
        assert!(SecurityClearance::Restricted < SecurityClearance::Confidential);
        assert!(SecurityClearance::Confidential < SecurityClearance::Secret);
        assert!(SecurityClearance::Secret < SecurityClearance::TopSecret);
    }
    
    #[test]
    fn test_approval_expiry() {
        let mut governance = PluginGovernance::new();
        
        // Create expired approval
        let expired_record = ApprovalRecord {
            plugin_name: "expired_plugin".to_string(),
            plugin_version: "1.0.0".to_string(),
            approval_status: ApprovalStatus::Approved,
            approval_date: chrono::Utc::now() - chrono::Duration::days(400),
            expiry_date: Some(chrono::Utc::now() - chrono::Duration::days(1)),
            approved_by: vec!["admin".to_string()],
            conditions: Vec::new(),
            review_notes: String::new(),
        };
        
        governance.approved_plugins.insert("expired_plugin".to_string(), expired_record);
        
        // Should not be approved due to expiry
        assert!(!governance.is_approved("expired_plugin"));
    }
}