//! comprehensive error types for ctdiff library
//! 
//! provides detailed error information with security considerations

use thiserror::Error;

/// main error type for all ctdiff operations
#[derive(Error, Debug)]
pub enum Error {
    /// input/output errors when reading files
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    
    /// security policy violations
    #[error("security violation: {message}")]
    Security { message: String },
    
    /// input validation failures
    #[error("invalid input: {message}")]
    InvalidInput { message: String },
    
    /// configuration errors
    #[error("configuration error: {message}")]
    Configuration { message: String },
    
    /// diff algorithm internal errors
    #[error("diff algorithm error: {0}")]
    Algorithm(#[from] crate::types::DiffError),
    
    /// format conversion errors
    #[error("format error: {message}")]
    Format { message: String },
    
    /// memory/resource limit violations
    #[error("resource limit exceeded: {message}")]
    ResourceLimit { message: String },
    
    /// encoding/decoding errors
    #[error("encoding error: {0}")]
    Encoding(#[from] std::string::FromUtf8Error),
    
    /// json serialization errors
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    
    /// async runtime errors (when async feature enabled)
    #[cfg(feature = "async")]
    #[error("async runtime error: {0}")]
    Runtime(#[from] tokio::task::JoinError),
}

impl Error {
    /// creates a security error with detailed message
    pub fn security(message: impl Into<String>) -> Self {
        Self::Security {
            message: message.into(),
        }
    }
    
    /// creates an invalid input error
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }
    
    /// creates a configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }
    
    /// creates a format error
    pub fn format(message: impl Into<String>) -> Self {
        Self::Format {
            message: message.into(),
        }
    }
    
    /// creates a resource limit error
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit {
            message: message.into(),
        }
    }
    
    /// checks if error is related to security
    pub fn is_security_error(&self) -> bool {
        matches!(self, Self::Security { .. })
    }
    
    /// checks if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Io(_) => true,
            Self::Security { .. } => false,
            Self::InvalidInput { .. } => true,
            Self::Configuration { .. } => true,
            Self::Algorithm(_) => false,
            Self::Format { .. } => true,
            Self::ResourceLimit { .. } => false,
            Self::Encoding(_) => true,
            Self::Json(_) => true,
            #[cfg(feature = "async")]
            Self::Runtime(_) => false,
        }
    }
}

/// result type alias for ctdiff operations
pub type Result<T> = std::result::Result<T, Error>;