//! API versioning and compatibility management

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// API version structure with semantic versioning
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVersion(pub semver::Version);

mod serde_semver {
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use semver::Version;

    pub fn serialize<S>(version: &Version, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        version.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Version::parse(&s).map_err(D::Error::custom)
    }
}

impl Serialize for ApiVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_semver::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for ApiVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_semver::deserialize(deserializer).map(ApiVersion)
    }
}

/// Compatibility check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compatibility {
    pub compatible: bool,
    pub reason: String,
    pub recommendation: Option<String>,
}

/// Version requirement specification using semver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionBounds(pub semver::VersionReq);

/// Version requirement specification (deprecated, use VersionBounds)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRequirement {
    pub operator: VersionOperator,
    pub version: ApiVersion,
}

/// Version comparison operators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VersionOperator {
    Exact,          // =1.0.0
    GreaterThan,    // >1.0.0
    GreaterEqual,   // >=1.0.0
    LessThan,       // <1.0.0
    LessEqual,      // <=1.0.0
    Compatible,     // ~1.0.0 (patch compatible)
    Semver,         // ^1.0.0 (minor compatible)
}

impl ApiVersion {
    /// Current API version
    pub fn current() -> Self {
        Self(semver::Version::new(1, 0, 0))
    }
    
    /// Create new API version
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self(semver::Version::new(major, minor, patch))
    }
    
    /// Create version with pre-release
    pub fn with_pre_release(major: u64, minor: u64, patch: u64, pre_release: &str) -> Result<Self, semver::Error> {
        let mut version = semver::Version::new(major, minor, patch);
        version.pre = semver::Prerelease::new(pre_release)?;
        Ok(Self(version))
    }
    
    /// Parse version string
    pub fn parse(version_str: &str) -> Result<Self, semver::Error> {
        semver::Version::parse(version_str).map(ApiVersion)
    }
    
    /// Access major version
    pub fn major(&self) -> u64 {
        self.0.major
    }
    
    /// Access minor version
    pub fn minor(&self) -> u64 {
        self.0.minor
    }
    
    /// Access patch version
    pub fn patch(&self) -> u64 {
        self.0.patch
    }
    
    pub fn is_compatible(&self, other: &ApiVersion) -> bool {
        self.check_compatibility(other).compatible
    }
    
    pub fn check_compatibility(&self, other: &ApiVersion) -> Compatibility {
        if self.0.major != other.0.major {
            return Compatibility {
                compatible: false,
                reason: format!("Major version mismatch: {} vs {}", self.0.major, other.0.major),
                recommendation: Some(format!("Upgrade to API version {}.x.x", self.0.major)),
            };
        }
        
        if self.0.minor < other.0.minor {
            return Compatibility {
                compatible: false,
                reason: format!("Minor version too old: {} vs {}", self.0.minor, other.0.minor),
                recommendation: Some(format!("Upgrade to API version {}.{}.x", self.0.major, other.0.minor)),
            };
        }
        
        if !other.0.pre.is_empty() && self.0.pre.is_empty() {
            return Compatibility {
                compatible: true,
                reason: "Plugin uses pre-release version".to_string(),
                recommendation: Some("Consider using stable version".to_string()),
            };
        }
        
        Compatibility {
            compatible: true,
            reason: "Versions are compatible".to_string(),
            recommendation: None,
        }
    }
    
    /// Check if version satisfies requirement
    pub fn satisfies(&self, requirement: &VersionRequirement) -> bool {
        match requirement.operator {
            VersionOperator::Exact => self == &requirement.version,
            VersionOperator::GreaterThan => self > &requirement.version,
            VersionOperator::GreaterEqual => self >= &requirement.version,
            VersionOperator::LessThan => self < &requirement.version,
            VersionOperator::LessEqual => self <= &requirement.version,
            VersionOperator::Compatible => self.is_patch_compatible(&requirement.version),
            VersionOperator::Semver => self.is_semver_compatible(&requirement.version),
        }
    }
    
    /// Check patch compatibility (~1.0.0 - same major.minor)
    fn is_patch_compatible(&self, other: &ApiVersion) -> bool {
        self.major == other.major && 
        self.minor == other.minor &&
        self.patch >= other.patch
    }
    
    /// Check semantic version compatibility (^1.0.0 - same major)
    fn is_semver_compatible(&self, other: &ApiVersion) -> bool {
        self.major == other.major &&
        (self.minor > other.minor || 
         (self.minor == other.minor && self.patch >= other.patch))
    }
    
    /// Parse version string (e.g., "1.0.0-alpha.1+build.123")
    pub fn parse(version_str: &str) -> Result<Self, VersionParseError> {
        let parts: Vec<&str> = version_str.split(&['+', '-'][..]).collect();
        
        if parts.is_empty() {
            return Err(VersionParseError::InvalidFormat);
        }
        
        // Parse major.minor.patch
        let version_parts: Vec<&str> = parts[0].split('.').collect();
        if version_parts.len() != 3 {
            return Err(VersionParseError::InvalidFormat);
        }
        
        let major = version_parts[0].parse::<u32>()
            .map_err(|_| VersionParseError::InvalidNumber)?;
        let minor = version_parts[1].parse::<u32>()
            .map_err(|_| VersionParseError::InvalidNumber)?;
        let patch = version_parts[2].parse::<u32>()
            .map_err(|_| VersionParseError::InvalidNumber)?;
        
        let mut pre_release = None;
        let mut build_metadata = None;
        
        // Parse pre-release and build metadata
        if parts.len() > 1 {
            // Check if we have both pre-release and build metadata
            if version_str.contains('-') && version_str.contains('+') {
                let pre_start = version_str.find('-').unwrap() + 1;
                let pre_end = version_str.find('+').unwrap();
                let build_start = pre_end + 1;
                
                pre_release = Some(version_str[pre_start..pre_end].to_string());
                build_metadata = Some(version_str[build_start..].to_string());
            } else if version_str.contains('-') {
                let pre_start = version_str.find('-').unwrap() + 1;
                pre_release = Some(version_str[pre_start..].to_string());
            } else if version_str.contains('+') {
                let build_start = version_str.find('+').unwrap() + 1;
                build_metadata = Some(version_str[build_start..].to_string());
            }
        }
        
        Ok(Self {
            major,
            minor,
            patch,
            pre_release,
            build_metadata,
        })
    }
    
    /// Get version as string
    pub fn to_string(&self) -> String {
        let mut version = format!("{}.{}.{}", self.major, self.minor, self.patch);
        
        if let Some(pre) = &self.pre_release {
            version.push('-');
            version.push_str(pre);
        }
        
        if let Some(build) = &self.build_metadata {
            version.push('+');
            version.push_str(build);
        }
        
        version
    }
    
    /// Check if version is stable (no pre-release)
    pub fn is_stable(&self) -> bool {
        self.pre_release.is_none()
    }
    
    /// Check if version is pre-release
    pub fn is_pre_release(&self) -> bool {
        self.pre_release.is_some()
    }
    
    /// Get next major version
    pub fn next_major(&self) -> Self {
        Self {
            major: self.major + 1,
            minor: 0,
            patch: 0,
            pre_release: None,
            build_metadata: None,
        }
    }
    
    /// Get next minor version
    pub fn next_minor(&self) -> Self {
        Self {
            major: self.major,
            minor: self.minor + 1,
            patch: 0,
            pre_release: None,
            build_metadata: None,
        }
    }
    
    /// Get next patch version
    pub fn next_patch(&self) -> Self {
        Self {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
            pre_release: None,
            build_metadata: None,
        }
    }
}

/// Version parsing error
#[derive(Debug, Clone, PartialEq)]
pub enum VersionParseError {
    InvalidFormat,
    InvalidNumber,
    Empty,
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionParseError::InvalidFormat => write!(f, "Invalid version format"),
            VersionParseError::InvalidNumber => write!(f, "Invalid version number"),
            VersionParseError::Empty => write!(f, "Empty version string"),
        }
    }
}

impl std::error::Error for VersionParseError {}

impl VersionBounds {
    pub fn parse(req_str: &str) -> Result<Self, semver::Error> {
        semver::VersionReq::parse(req_str).map(VersionBounds)
    }
    
    pub fn matches(&self, version: &ApiVersion) -> bool {
        self.0.matches(&version.0)
    }
    
    pub fn any() -> Self {
        Self(semver::VersionReq::STAR)
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialOrd for ApiVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for ApiVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl VersionRequirement {
    /// Create exact version requirement
    pub fn exact(version: ApiVersion) -> Self {
        Self {
            operator: VersionOperator::Exact,
            version,
        }
    }
    
    /// Create semver compatible requirement
    pub fn semver_compatible(version: ApiVersion) -> Self {
        Self {
            operator: VersionOperator::Semver,
            version,
        }
    }
    
    /// Create patch compatible requirement
    pub fn patch_compatible(version: ApiVersion) -> Self {
        Self {
            operator: VersionOperator::Compatible,
            version,
        }
    }
    
    /// Parse requirement string (e.g., ">=1.0.0", "~1.0.0", "^1.0.0")
    pub fn parse(requirement_str: &str) -> Result<Self, VersionParseError> {
        let (operator, version_str) = if requirement_str.starts_with(">=") {
            (VersionOperator::GreaterEqual, &requirement_str[2..])
        } else if requirement_str.starts_with("<=") {
            (VersionOperator::LessEqual, &requirement_str[2..])
        } else if requirement_str.starts_with('>') {
            (VersionOperator::GreaterThan, &requirement_str[1..])
        } else if requirement_str.starts_with('<') {
            (VersionOperator::LessThan, &requirement_str[1..])
        } else if requirement_str.starts_with('~') {
            (VersionOperator::Compatible, &requirement_str[1..])
        } else if requirement_str.starts_with('^') {
            (VersionOperator::Semver, &requirement_str[1..])
        } else if requirement_str.starts_with('=') {
            (VersionOperator::Exact, &requirement_str[1..])
        } else {
            (VersionOperator::Exact, requirement_str)
        };
        
        let version = ApiVersion::parse(version_str)?;
        
        Ok(Self {
            operator,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let version = ApiVersion::parse("1.2.3").unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert!(version.pre_release.is_none());
        assert!(version.build_metadata.is_none());
    }
    
    #[test]
    fn test_version_with_pre_release() {
        let version = ApiVersion::parse("1.2.3-alpha.1").unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert_eq!(version.pre_release, Some("alpha.1".to_string()));
    }
    
    #[test]
    fn test_version_with_build_metadata() {
        let version = ApiVersion::parse("1.2.3+build.123").unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
        assert_eq!(version.build_metadata, Some("build.123".to_string()));
    }
    
    #[test]
    fn test_version_comparison() {
        let v1 = ApiVersion::new(1, 0, 0);
        let v2 = ApiVersion::new(1, 0, 1);
        let v3 = ApiVersion::new(1, 1, 0);
        let v4 = ApiVersion::new(2, 0, 0);
        
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
    }
    
    #[test]
    fn test_compatibility_check() {
        let current = ApiVersion::new(1, 2, 0);
        let plugin = ApiVersion::new(1, 1, 0);
        
        let compatibility = current.check_compatibility(&plugin);
        assert!(compatibility.compatible);
        
        let future_plugin = ApiVersion::new(2, 0, 0);
        let compatibility = current.check_compatibility(&future_plugin);
        assert!(!compatibility.compatible);
    }
    
    #[test]
    fn test_version_requirements() {
        let version = ApiVersion::new(1, 2, 3);
        
        let exact_req = VersionRequirement::exact(ApiVersion::new(1, 2, 3));
        assert!(version.satisfies(&exact_req));
        
        let semver_req = VersionRequirement::semver_compatible(ApiVersion::new(1, 2, 0));
        assert!(version.satisfies(&semver_req));
        
        let patch_req = VersionRequirement::patch_compatible(ApiVersion::new(1, 2, 0));
        assert!(version.satisfies(&patch_req));
    }
    
    #[test]
    fn test_version_string_conversion() {
        let version = ApiVersion::parse("1.2.3-alpha.1+build.123").unwrap();
        assert_eq!(version.to_string(), "1.2.3-alpha.1+build.123");
    }
    
    #[test]
    fn test_requirement_parsing() {
        let req = VersionRequirement::parse(">=1.0.0").unwrap();
        assert_eq!(req.operator, VersionOperator::GreaterEqual);
        assert_eq!(req.version, ApiVersion::new(1, 0, 0));
        
        let req = VersionRequirement::parse("~1.2.3").unwrap();
        assert_eq!(req.operator, VersionOperator::Compatible);
        assert_eq!(req.version, ApiVersion::new(1, 2, 3));
        
        let req = VersionRequirement::parse("^1.0.0").unwrap();
        assert_eq!(req.operator, VersionOperator::Semver);
        assert_eq!(req.version, ApiVersion::new(1, 0, 0));
    }
}