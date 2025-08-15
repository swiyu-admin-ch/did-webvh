// SPDX-License-Identifier: MIT

//use std::cmp::PartialEq;

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WebVerfiableHistoryIdResolutionError {
    /// DID method is not supported by this resolver.
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
}

impl WebVerfiableHistoryIdResolutionError {
    /// Returns the error kind.
    pub fn kind(&self) -> WebVerfiableHistoryIdResolutionErrorKind {
        match self {
            Self::MethodNotSupported(_) => {
                WebVerfiableHistoryIdResolutionErrorKind::MethodNotSupported
            }
            Self::InvalidMethodSpecificId(_) => {
                WebVerfiableHistoryIdResolutionErrorKind::InvalidMethodSpecificId
            }
        }
    }
}

/// WebVerfiableHistoryIdResolutionError kind.
///
/// Each [`WebVerfiableHistoryIdResolutionError`] has a kind provided by the [`WebVerifiedHistoryIdResolutionErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebVerfiableHistoryIdResolutionErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
}

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WebVerfiableHistoryError {
    /// DID method is not supported by this resolver
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
    /// Failed to serialize DID document (to JSON)
    #[error("failed to serialize DID document (to JSON): {0}")]
    SerializationFailed(String),
    /// The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation
    #[error("The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation: {0}"
    )]
    DeserializationFailed(String),
    /// Invalid (or not yet supported) operation against DID doc
    #[error("invalid (or not yet supported) operation against DID doc: {0}")]
    InvalidOperation(String),
    /// Invalid DID parameter
    #[error("invalid DID parameter: {0}")]
    InvalidDidParameter(String),
    /// Invalid DID document
    #[error("invalid DID document: {0}")]
    InvalidDidDocument(String),
    /// Invalid DID log integration proof
    #[error("invalid DID log integration proof: {0}")]
    InvalidDataIntegrityProof(String),
}

impl WebVerfiableHistoryError {
    /// Returns the error kind.
    pub fn kind(&self) -> WebVerfiableHistoryErrorKind {
        match self {
            Self::MethodNotSupported(_) => WebVerfiableHistoryErrorKind::MethodNotSupported,
            Self::InvalidMethodSpecificId(_) => {
                WebVerfiableHistoryErrorKind::InvalidMethodSpecificId
            }
            Self::SerializationFailed(_) => WebVerfiableHistoryErrorKind::SerializationFailed,
            Self::DeserializationFailed(_) => WebVerfiableHistoryErrorKind::DeserializationFailed,
            Self::InvalidOperation(_) => WebVerfiableHistoryErrorKind::InvalidOperation,
            Self::InvalidDidParameter(_) => WebVerfiableHistoryErrorKind::InvalidDidParameter,
            Self::InvalidDidDocument(_) => WebVerfiableHistoryErrorKind::InvalidDidDocument,
            Self::InvalidDataIntegrityProof(_) => {
                WebVerfiableHistoryErrorKind::InvalidIntegrityProof
            }
        }
    }
}

/// WebVerfiableHistoryError kind.
///
/// Each [`WebVerfiableHistorybError`] has a kind provided by the [`WebVerifiedHistoryErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebVerfiableHistoryErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
    SerializationFailed,
    DeserializationFailed,
    InvalidOperation,
    InvalidDidParameter,
    InvalidDidDocument,
    InvalidIntegrityProof,
}
