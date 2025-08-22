// SPDX-License-Identifier: MIT

//use std::cmp::PartialEq;

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WebVerifiableHistoryIdResolutionError {
    /// DID method is not supported by this resolver.
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
}

impl WebVerifiableHistoryIdResolutionError {
    /// Returns the error kind.
    pub fn kind(&self) -> WebVerifiableHistoryIdResolutionErrorKind {
        match self {
            Self::MethodNotSupported(_) => {
                WebVerifiableHistoryIdResolutionErrorKind::MethodNotSupported
            }
            Self::InvalidMethodSpecificId(_) => {
                WebVerifiableHistoryIdResolutionErrorKind::InvalidMethodSpecificId
            }
        }
    }
}

/// WebVerfiableHistoryIdResolutionError kind.
///
/// Each [`WebVerifiableHistoryIdResolutionError`] has a kind provided by the [`WebVerifiableHistoryIdResolutionErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebVerifiableHistoryIdResolutionErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
}

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum WebVerifiableHistoryError {
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

impl WebVerifiableHistoryError {
    /// Returns the error kind.
    pub fn kind(&self) -> WebVerifiableHistoryErrorKind {
        match self {
            Self::MethodNotSupported(_) => WebVerifiableHistoryErrorKind::MethodNotSupported,
            Self::InvalidMethodSpecificId(_) => {
                WebVerifiableHistoryErrorKind::InvalidMethodSpecificId
            }
            Self::SerializationFailed(_) => WebVerifiableHistoryErrorKind::SerializationFailed,
            Self::DeserializationFailed(_) => WebVerifiableHistoryErrorKind::DeserializationFailed,
            Self::InvalidOperation(_) => WebVerifiableHistoryErrorKind::InvalidOperation,
            Self::InvalidDidParameter(_) => WebVerifiableHistoryErrorKind::InvalidDidParameter,
            Self::InvalidDidDocument(_) => WebVerifiableHistoryErrorKind::InvalidDidDocument,
            Self::InvalidDataIntegrityProof(_) => {
                WebVerifiableHistoryErrorKind::InvalidIntegrityProof
            }
        }
    }
}

/// WebVerfiableHistoryError kind.
///
/// Each [`WebVerfiableHistorybError`] has a kind provided by the [`WebVerifiedHistoryErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WebVerifiableHistoryErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
    SerializationFailed,
    DeserializationFailed,
    InvalidOperation,
    InvalidDidParameter,
    InvalidDidDocument,
    InvalidIntegrityProof,
}
