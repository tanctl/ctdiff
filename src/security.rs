//! security configuration and levels
//! 
//! defines security policies and configurations for constant-time operations

use crate::types::SecurityConfig as LegacySecurityConfig;

/// high-level security levels for easy configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// maximum security with strong timing attack resistance
    Maximum,
    /// balanced performance and security for most use cases
    Balanced,
    /// performance optimized with basic security
    Fast,
}

impl SecurityLevel {
    /// converts security level to detailed configuration
    pub fn to_config(self, max_size: Option<usize>) -> SecurityConfig {
        match self {
            SecurityLevel::Maximum => SecurityConfig::maximum_security(max_size),
            SecurityLevel::Balanced => SecurityConfig::balanced(max_size),
            SecurityLevel::Fast => SecurityConfig::fast(max_size),
        }
    }
}

/// detailed security configuration for diff operations
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// maximum input size in bytes
    pub max_input_size: usize,
    /// whether to pad inputs to fixed size
    pub pad_inputs: bool,
    /// padding size for inputs (none = auto-calculate)
    pub padding_size: Option<usize>,
    /// whether to validate inputs for security
    pub validate_inputs: bool,
    /// maximum edit distance allowed
    pub max_edit_distance: Option<usize>,
    /// enable memory protection features
    pub memory_protection: bool,
    /// constant-time guarantees level
    pub timing_protection: TimingProtection,
}

/// timing protection levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingProtection {
    /// maximum constant-time guarantees
    Strict,
    /// balanced timing protection
    Moderate,
    /// basic timing protection
    Basic,
    /// no timing protection (fast but vulnerable)
    None,
}

impl SecurityConfig {
    /// maximum security configuration
    pub fn maximum_security(max_size: Option<usize>) -> Self {
        let max_input_size = max_size.unwrap_or(4 * 1024); // 4kb default
        Self {
            max_input_size,
            pad_inputs: true,
            padding_size: Some(max_input_size.next_power_of_two()),
            validate_inputs: true,
            max_edit_distance: Some(max_input_size / 2),
            memory_protection: true,
            timing_protection: TimingProtection::Strict,
        }
    }
    
    /// balanced security and performance
    pub fn balanced(max_size: Option<usize>) -> Self {
        let max_input_size = max_size.unwrap_or(256 * 1024); // 256kb default
        Self {
            max_input_size,
            pad_inputs: true,
            padding_size: None, // auto-calculate
            validate_inputs: true,
            max_edit_distance: Some(max_input_size / 4),
            memory_protection: true,
            timing_protection: TimingProtection::Moderate,
        }
    }
    
    /// fast configuration with minimal security
    pub fn fast(max_size: Option<usize>) -> Self {
        let max_input_size = max_size.unwrap_or(1024 * 1024); // 1mb default
        Self {
            max_input_size,
            pad_inputs: false,
            padding_size: None,
            validate_inputs: false,
            max_edit_distance: None,
            memory_protection: false,
            timing_protection: TimingProtection::Basic,
        }
    }
    
    /// no security (for benchmarking only)
    pub fn insecure() -> Self {
        Self {
            max_input_size: usize::MAX,
            pad_inputs: false,
            padding_size: None,
            validate_inputs: false,
            max_edit_distance: None,
            memory_protection: false,
            timing_protection: TimingProtection::None,
        }
    }
    
    /// converts to legacy security config for compatibility
    pub fn to_legacy(&self) -> LegacySecurityConfig {
        LegacySecurityConfig {
            max_input_size: self.max_input_size,
            pad_inputs: self.pad_inputs,
            padding_size: self.padding_size,
            validate_inputs: self.validate_inputs,
            max_edit_distance: self.max_edit_distance,
        }
    }
    
    /// validates configuration for security issues
    pub fn validate(&self) -> crate::Result<()> {
        if self.timing_protection == TimingProtection::None {
            return Err(crate::Error::security(
                "timing protection disabled - vulnerable to timing attacks"
            ));
        }
        
        if self.max_input_size > 10 * 1024 * 1024 && self.timing_protection == TimingProtection::Strict {
            return Err(crate::Error::security(
                "large inputs with strict timing protection may cause performance issues"
            ));
        }
        
        if !self.memory_protection && self.timing_protection != TimingProtection::None {
            log_warning("memory protection disabled but timing protection enabled");
        }
        
        Ok(())
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::balanced(None)
    }
}

// helper function for logging warnings (placeholder)
fn log_warning(_msg: &str) {
    // implementation would depend on logging framework
    eprintln!("warning: {}", _msg);
}