//! Cryptographic signatures for forensic reports

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cryptographic signature for forensic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSignature {
    pub signature_id: Uuid,
    pub public_key: String,
    pub signature: String,
    pub signature_algorithm: String,
    pub signed_at: DateTime<Utc>,
    pub signer_role: String,
    pub signature_purpose: String,
    pub hash_algorithm: String,
    pub signed_hash: String,
}

/// Signature verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub signature_id: Uuid,
    pub is_valid: bool,
    pub verification_time: DateTime<Utc>,
    pub error_message: Option<String>,
    pub public_key_info: Option<PublicKeyInfo>,
}

/// Public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub key_size: usize,
    pub fingerprint: String,
    pub owner: Option<String>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

/// Signature policy for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePolicy {
    pub minimum_signatures: usize,
    pub required_roles: Vec<String>,
    pub signature_algorithm: String,
    pub hash_algorithm: String,
    pub require_timestamp: bool,
    pub max_signature_age_hours: Option<u64>,
}

impl Default for SignaturePolicy {
    fn default() -> Self {
        Self {
            minimum_signatures: 1,
            required_roles: vec!["investigator".to_string()],
            signature_algorithm: "Ed25519".to_string(),
            hash_algorithm: "SHA256".to_string(),
            require_timestamp: true,
            max_signature_age_hours: Some(24 * 365), // 1 year
        }
    }
}

impl SignaturePolicy {
    /// Validate signatures against policy
    pub fn validate_signatures(&self, signatures: &[ReportSignature]) -> Result<bool, String> {
        // Check minimum signature count
        if signatures.len() < self.minimum_signatures {
            return Err(format!(
                "Insufficient signatures: {} required, {} provided",
                self.minimum_signatures,
                signatures.len()
            ));
        }
        
        // Check required roles
        for required_role in &self.required_roles {
            if !signatures.iter().any(|sig| sig.signer_role == *required_role) {
                return Err(format!("Missing required role: {}", required_role));
            }
        }
        
        // Check signature algorithms
        for signature in signatures {
            if signature.signature_algorithm != self.signature_algorithm {
                return Err(format!(
                    "Invalid signature algorithm: {} (expected: {})",
                    signature.signature_algorithm,
                    self.signature_algorithm
                ));
            }
        }
        
        // Check signature age if specified
        if let Some(max_age_hours) = self.max_signature_age_hours {
            let now = Utc::now();
            for signature in signatures {
                let age = now.signed_duration_since(signature.signed_at);
                if age.num_hours() > max_age_hours as i64 {
                    return Err(format!(
                        "Signature too old: {} hours (max: {} hours)",
                        age.num_hours(),
                        max_age_hours
                    ));
                }
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_policy_validation() {
        let policy = SignaturePolicy::default();
        
        let signature = ReportSignature {
            signature_id: Uuid::new_v4(),
            public_key: "test_key".to_string(),
            signature: "test_signature".to_string(),
            signature_algorithm: "Ed25519".to_string(),
            signed_at: Utc::now(),
            signer_role: "investigator".to_string(),
            signature_purpose: "Report Validation".to_string(),
            hash_algorithm: "SHA256".to_string(),
            signed_hash: "test_hash".to_string(),
        };
        
        let signatures = vec![signature];
        assert!(policy.validate_signatures(&signatures).is_ok());
    }
    
    #[test]
    fn test_insufficient_signatures() {
        let mut policy = SignaturePolicy::default();
        policy.minimum_signatures = 2;
        
        let signature = ReportSignature {
            signature_id: Uuid::new_v4(),
            public_key: "test_key".to_string(),
            signature: "test_signature".to_string(),
            signature_algorithm: "Ed25519".to_string(),
            signed_at: Utc::now(),
            signer_role: "investigator".to_string(),
            signature_purpose: "Report Validation".to_string(),
            hash_algorithm: "SHA256".to_string(),
            signed_hash: "test_hash".to_string(),
        };
        
        let signatures = vec![signature];
        assert!(policy.validate_signatures(&signatures).is_err());
    }
}
