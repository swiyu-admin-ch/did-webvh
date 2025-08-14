// SPDX-License-Identifier: MIT

use crate::did_webvh_jsonschema::DidLogEntryJsonSchema;
use crate::did_webvh_parameters::*;
use crate::errors::*;
use chrono::serde::ts_seconds;
use chrono::{DateTime, SecondsFormat, Utc};
use did_sidekicks::did_doc::*;
use did_sidekicks::did_jsonschema::DidLogEntryValidator;
use did_sidekicks::ed25519::*;
use did_sidekicks::jcs_sha256_hasher::JcsSha256Hasher;
use did_sidekicks::vc_data_integrity::{
    CryptoSuiteType, DataIntegrityProof, EddsaJcs2022Cryptosuite, VCDataIntegrity,
};
use rayon::prelude::*;
use regex;
use regex::Regex;
use serde::de;
use serde::{Deserialize, Serialize};
use serde_json::Value::Object as JsonObject;
use serde_json::{
    from_str as json_from_str, json, to_string as json_to_string, Value as JsonValue,
};
use std::cmp::PartialEq;
use std::sync::{Arc, LazyLock};
use url::Url;
use url_escape;

pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const DID_LOG_ENTRY_VERSION_ID: &str = "versionId";
pub const DID_LOG_ENTRY_VERSION_TIME: &str = "versionTime";
pub const DID_LOG_ENTRY_PARAMETERS: &str = "parameters";
pub const DID_LOG_ENTRY_STATE: &str = "state";
pub const DID_LOG_ENTRY_PROOF: &str = "proof";

/// Entry in a did log file as shown here
/// https://identity.foundation/didwebvh/v1.0/#term:did-log-entry
#[derive(Serialize, Debug, Clone)]
pub struct DidLogEntry {
    /// Since v0.2 (see https://identity.foundation/didwebvh/v1.0/#didwebvh-version-changelog):
    ///            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    #[serde(rename = "versionId")]
    pub version: DidLogVersion,

    #[serde(rename = "versionTime")]
    #[serde(with = "ts_seconds")]
    pub version_time: DateTime<Utc>,

    #[serde(rename = "parameters")]
    pub parameters: DidMethodParameters,

    #[serde(rename = "state")]
    pub did_doc: DidDoc,

    #[serde(skip)]
    pub did_doc_json: JsonValue,

    #[serde(rename = "proof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<DataIntegrityProof>>,

    #[serde(skip)]
    prev_entry: Option<Arc<DidLogEntry>>, // Arc-ed to prevent "recursive without indirection"
}

#[derive(Debug, Clone)]
pub struct DidLogVersion {
    pub id: String,
    pub index: usize,
    pub hash: String,
}

impl DidLogVersion {
    fn new(hash: &str) -> Self {
        Self {
            id: hash.to_string(),
            index: 0,
            hash: hash.to_string(),
        }
    }
}

impl Serialize for DidLogVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.id)
    }
}

impl<'de> Deserialize<'de> for DidLogVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(DidLogVersionVisitor)
    }
}

pub struct DidLogVersionVisitor;

impl<'de> de::Visitor<'de> for DidLogVersionVisitor {
    type Value = DidLogVersion;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a versionId in the format '<version_index>-<hash>'")
    }

    fn visit_str<E>(self, cmd_str: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        let id = cmd_str.to_string();
        let (index, hash) = id
            .split_once("-")
            .map(|(index, hash)| (index.parse::<usize>().unwrap(), hash.to_string())) // no panic is expected here...
            .unwrap();
        Ok(Self::Value { id, index, hash })
    }
}

impl DidLogEntry {
    #[allow(clippy::too_many_arguments)]
    /// Import of existing log entry
    pub fn new(
        version: DidLogVersion,
        version_time: DateTime<Utc>,
        parameters: DidMethodParameters,
        did_doc: DidDoc,
        did_doc_json: JsonValue,
        proof: DataIntegrityProof,
        prev_entry: Option<Arc<DidLogEntry>>,
    ) -> Self {
        DidLogEntry {
            version,
            version_time,
            parameters,
            did_doc,
            did_doc_json,
            proof: Some(vec![proof]),
            prev_entry,
        }
    }

    /// Check whether the versionId of this log entry is based on the previous versionId
    pub fn verify_version_id_integrity(&self) -> Result<(), TrustDidWebError> {
        // 1 Extract the versionId in the DID log entry, and remove from it the version number and dash prefix, leaving the log entry entryHash value.
        let hash = &self.version.hash;
        let calculated_hash = self.calculate_entry_hash().map_err(|err| {
            TrustDidWebError::InvalidDataIntegrityProof(format!("Failed to build versionId: {err}"))
        })?;
        if calculated_hash != *hash {
            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                "Invalid DID log. The DID log entry has invalid entry hash: {}. Expected: {}",
                hash, calculated_hash,
            )));
        }
        Ok(())
    }

    /// Check whether the integrity proof matches the content of the did document of this log entry
    pub fn verify_data_integrity_proof(&self) -> Result<(), TrustDidWebError> {
        match &self.proof {
            None => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Invalid did log. Proof is empty.".to_string(),
                ))
            }
            Some(v) => {
                if v.is_empty() {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Invalid did log. Proof is empty.".to_string(),
                    ));
                }

                let prev = match self.prev_entry.as_ref() {
                    None => self,
                    Some(e) => e,
                };
                for proof in v {
                    let update_key = match proof.extract_update_key() {
                        Ok(key) => key,
                        Err(err) => {
                            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                                "Failed to extract update key due to: {err}"
                            )))
                        }
                    };

                    let verifying_key = prev.is_key_authorized_for_update(update_key)?;

                    if !matches!(proof.crypto_suite_type, Some(CryptoSuiteType::EddsaJcs2022)) {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Unsupported proof's cryptosuite {}",
                            proof.crypto_suite
                        )));
                    }

                    let cryptosuite = EddsaJcs2022Cryptosuite {
                        verifying_key: Some(verifying_key),
                        signing_key: None,
                    };

                    // use entire DidLogEntry for signature
                    let doc = DidLogEntry {
                        version: self.version.clone(),
                        version_time: self.version_time,
                        parameters: self.parameters.clone(),
                        did_doc: self.did_doc.clone(),
                        did_doc_json: self.did_doc_json.clone(),
                        proof: None,
                        prev_entry: None,
                    }
                    .to_log_entry_line()?;

                    let doc_hash = JcsSha256Hasher::default().encode_hex(&doc).unwrap();

                    match cryptosuite.verify_proof(proof, doc_hash.as_str()) {
                        Ok(_) => (),
                        Err(err) => {
                            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                                "Failed to verify proof due to: {err}"
                            )))
                        }
                    };
                }
            }
        };
        Ok(())
    }

    /// The new versionId takes the form \<version number\>-\<entryHash\>, where \<version number\> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    pub fn calculate_entry_hash(&self) -> Result<String, TrustDidWebError> {
        // According to https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification
        // 2 Determine hash algorithm, as specified by TODO, is base58btc
        // 3 Set the versionId in the entry object to be the versionId from the previous log entry.
        //   If this is the first entry in the log, set the value to <scid>, the value of the SCID of the DID.
        let prev_version_id = match &self.prev_entry {
            Some(v) => v.version.id.clone(),
            None => match self.parameters.scid.clone() {
                Some(v) => v,
                None => {
                    return Err(TrustDidWebError::DeserializationFailed(
                        "Error extracting scid".to_string(),
                    ))
                }
            },
        };
        // 4. remove Data Integrity proof from the log entry
        let entry = DidLogEntry {
            version: DidLogVersion::new(&prev_version_id),
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            proof: None,
            prev_entry: None,
        };
        let entry_json = entry.to_log_entry_line()?;
        // 5 calculate  the hash string
        let calculated_hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&entry_json)
            .map_err(|err| {
                TrustDidWebError::SerializationFailed(format!("Failed to encode multihash: {err}"))
            })?;
        Ok(calculated_hash)
    }

    fn is_key_authorized_for_update(
        &self,
        update_key: String,
    ) -> Result<Ed25519VerifyingKey, TrustDidWebError> {
        match &self.parameters.update_keys {
            Some(update_keys) => {
                if update_keys.is_empty() {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "No update keys detected".to_string(),
                    ));
                }

                match update_keys.iter().find(|entry| *entry == &update_key) {
                    Some(_) => {}
                    _ => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Key extracted from proof is not authorized for update: {update_key}"
                        )))
                    }
                };

                let verifying_key = match Ed25519VerifyingKey::from_multibase(update_key.as_str()) {
                    Ok(key) => key,
                    Err(err) => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                        "Failed to convert update key (from its multibase representation): {err}"
                    )))
                    }
                };

                Ok(verifying_key)
            }
            None => {
                let prev_entry = match self.prev_entry.to_owned() {
                    Some(e) => e,
                    _ => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "No update keys detected".to_string(),
                        ));
                    }
                };
                prev_entry.is_key_authorized_for_update(update_key) // recursive call
            }
        }
    }

    fn to_log_entry_line(&self) -> Result<JsonValue, TrustDidWebError> {
        let did_doc_json_value = self.did_doc_json.clone();

        let version_time = self
            .version_time
            .to_owned()
            .to_rfc3339_opts(SecondsFormat::Secs, true)
            .to_string();

        let mut entry = json!({
            DID_LOG_ENTRY_VERSION_ID: self.version.id,
            DID_LOG_ENTRY_VERSION_TIME: version_time,
            DID_LOG_ENTRY_PARAMETERS: self.parameters,
            DID_LOG_ENTRY_STATE: did_doc_json_value,
        });

        if let Some(proof) = &self.proof {
            let first_proof = match proof.first() {
                Some(v) => v,
                None => {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Invalid did log. Proof is empty.".to_string(),
                    ))
                }
            };

            let first_proof_json_val = match first_proof.json_value() {
                Ok(val) => val,
                Err(err) => return Err(TrustDidWebError::SerializationFailed(format!("{err}"))),
            };
            entry[DID_LOG_ENTRY_PROOF] = json!(vec![first_proof_json_val]);
        }

        Ok(entry)
    }

    fn build_original_scid(&self, scid: &String) -> serde_json::Result<String> {
        let did_doc_with_placeholder_scid = str::replace(
            self.did_doc_json.to_string().as_str(),
            scid,
            SCID_PLACEHOLDER,
        );

        let entry_with_placeholder_without_proof = json!({
           DID_LOG_ENTRY_VERSION_ID: SCID_PLACEHOLDER,
           DID_LOG_ENTRY_VERSION_TIME: self.version_time,
           DID_LOG_ENTRY_PARAMETERS: json_from_str::<JsonValue>(str::replace(json_to_string(&self.parameters)?.as_str(), scid, SCID_PLACEHOLDER).as_str())?,
           DID_LOG_ENTRY_STATE : json_from_str::<JsonValue>(did_doc_with_placeholder_scid.as_str())?,
        });

        let hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&entry_with_placeholder_without_proof)?;
        Ok(hash)
    }
}

#[derive(Serialize, Debug)]
pub struct DidDocumentState {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub did_log_entries: Vec<DidLogEntry>,
}

impl DidDocumentState {
    pub fn from(did_log: String) -> Result<Self, TrustDidWebError> {
        // CAUTION Despite parallelization, bear in mind that (according to benchmarks) the overall
        //         performance improvement will be considerable only in case of larger DID logs,
        //         featuring at least as many entries as `std::thread::available_parallelism()` would return.
        let validator =
            DidLogEntryValidator::from(DidLogEntryJsonSchema::V1_0EidConform.as_schema());
        if let Some(err) = did_log
            .par_lines() // engage a parallel iterator (thanks to 'use rayon::prelude::*;' import)
            // Once a non-None value is produced from the map operation,
            // `find_map_any` will attempt to stop processing the rest of the items in the iterator as soon as possible.
            .find_map_any(|line| validator.validate_str(line).err())
        {
            // The supplied DID log contains at least one entry that violates the JSON schema
            return Err(TrustDidWebError::DeserializationFailed(err.to_string()));
        }

        let mut current_params: Option<DidMethodParameters> = None;
        let mut prev_entry: Option<Arc<DidLogEntry>> = None;

        let mut is_deactivated: bool = false;
        //let now= Local::now();
        let now = Utc::now();

        Ok(DidDocumentState {
            did_log_entries: did_log
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| {
                    if is_deactivated {
                        return Err(TrustDidWebError::InvalidDidDocument(
                            "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_string()
                        ));
                    }

                    // CAUTION: It is assumed that the did:webvh JSON schema conformity check (see above)
                    //          have already been ensured at this point! 
                    //          Therefore, at this point, the current DID log entry may be considered fully JSON-schema-compliant, so...
                    let entry: JsonValue = serde_json::from_str(line).unwrap();     // ...no panic is expected here
                    let version: DidLogVersion = match serde_json::from_str(entry[DID_LOG_ENTRY_VERSION_ID].to_string().as_str()) {
                        Ok(v) => v,
                        Err(err) => {return Err(TrustDidWebError::DeserializationFailed(format!("Invalid versionId: {}", err)));},
                    };

                    if prev_entry.is_none() && version.index != 1
                        || prev_entry.is_some() && (version.index - 1).ne(&prev_entry.to_owned().unwrap().version.index) {
                        return Err(TrustDidWebError::DeserializationFailed("Version numbers (`versionId`) must be in a sequence of positive consecutive integers.".to_string()));
                    }

                    // https://identity.foundation/didwebvh/v1.0/#the-did-log-file:
                    // The `versionTime` (as stated by the DID Controller) of the entry,
                    // in ISO8601 format (https://identity.foundation/didwebvh/v0.3/#term:iso8601).
                    let version_time = entry[DID_LOG_ENTRY_VERSION_TIME].as_str()
                        .map(|s| DateTime::parse_from_rfc3339(s)
                            .unwrap() // no panic is expected here...
                            .to_utc())
                        .unwrap(); // ...or here (as the entry has already been validated)

                    // CAUTION This check is not really required as it has been already implemented by the JSON schema validator
                    if version_time.ge(&now) {
                        return Err(TrustDidWebError::DeserializationFailed(format!("`versionTime` '{version_time}' must be before the current datetime '{now}'.")));
                    }

                    if prev_entry.is_some() && version_time.lt(&prev_entry.to_owned().unwrap().version_time) {
                        return Err(TrustDidWebError::DeserializationFailed("`versionTime` must be greater then the `versionTime` of the previous entry.".to_string()));
                    }

                    let mut new_params: Option<DidMethodParameters> = None;
                    current_params = match entry[DID_LOG_ENTRY_PARAMETERS] {
                        JsonObject(ref obj) => {
                            if !obj.is_empty() {
                                new_params = Some(DidMethodParameters::from_json(&entry[DID_LOG_ENTRY_PARAMETERS].to_string())?);
                            }

                            match (current_params.clone(), new_params.clone()) {
                                (None, None) => return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document parameters.".to_string(),
                                )),
                                (None, Some(new_params)) => {
                                    // this is the first entry, therefore we check for the base configuration
                                    new_params.validate_initial()?;

                                    Some(new_params) // from the initial log entry
                                }
                                (Some(current_params), None) => {
                                    new_params = Some(DidMethodParameters::empty());
                                    Some(current_params.to_owned())
                                }
                                (Some(current_params), Some(new_params)) => {
                                    let mut _current_params = current_params.to_owned();
                                    _current_params.merge_from(&new_params)?;
                                    Some(_current_params)
                                }
                            }
                        }
                        _ => {
                            return Err(TrustDidWebError::DeserializationFailed(
                                "Missing DID Document parameters.".to_string(),
                            ))
                        }
                    };

                    is_deactivated = current_params.to_owned().is_some_and(|p| p.deactivated.is_some_and(|d| d));
                    if is_deactivated {
                        // https://identity.foundation/didwebvh/v1.0/#deactivate-revoke:
                        // To deactivate the DID, the DID Controller SHOULD add to the DID log entry parameters the item "deactivated": true.
                        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID,
                        // such as including an empty updateKeys list ("updateKeys": []) in the parameters,
                        // preventing further versions of the DID.
                        if let Some(mut _current_params) = current_params.to_owned() {
                            _current_params.deactivate();
                            current_params = Some(_current_params);
                        }
                    }

                    let did_doc_value = entry[DID_LOG_ENTRY_STATE].to_owned();
                    let current_did_doc: DidDoc = match did_doc_value {
                        JsonObject(_) => {
                            if did_doc_value.is_null() {
                                return Err(TrustDidWebError::DeserializationFailed(
                                    "DID Document was empty.".to_string(),
                                ));
                            }

                            let json = entry[DID_LOG_ENTRY_STATE].to_string();

                            match serde_json::from_str::<DidDoc>(&json) {
                                Ok(did_doc) => did_doc,
                                Err(_) => {
                                    match serde_json::from_str::<DidDocNormalized>(&json) {
                                        Ok(did_doc_alt) => {
                                            match did_doc_alt.to_did_doc() {
                                                Ok(doc) => doc,
                                                Err(err) => return Err(TrustDidWebError::DeserializationFailed(format!(
                                                    "Deserialization of DID document failed due to: {err}"
                                                ))),
                                            }
                                        }
                                        Err(err) => return Err(TrustDidWebError::DeserializationFailed(
                                            format!("Missing DID document: {err}")
                                        ))
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(TrustDidWebError::DeserializationFailed(
                                "Missing DID Document.".to_string(),
                            ))
                        }
                    };

                    let proof = match DataIntegrityProof::from(entry[DID_LOG_ENTRY_PROOF].to_string()) {
                        Ok(p) => p,
                        Err(err) => return Err(TrustDidWebError::DeserializationFailed(format!(
                            "Failed to deserialize data integrity proof due to: {err}"
                        ))),
                    };

                    let parameters = match new_params {
                        Some(new_params) => new_params,
                        None => return Err(TrustDidWebError::DeserializationFailed(
                            "Internal error: Missing parameter values.".to_string(),
                        ))
                    };

                    let current_entry = DidLogEntry::new(
                        version,
                        version_time,
                        parameters,
                        current_did_doc,
                        did_doc_value,
                        proof,
                        prev_entry.clone(),
                    );
                    prev_entry = Some(Arc::from(current_entry.clone()));

                    Ok(current_entry)
                }).collect::<Result<Vec<DidLogEntry>, TrustDidWebError>>()?
        })
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate_with_scid(
        &self,
        scid_to_validate: Option<String>,
    ) -> Result<Arc<DidDoc>, TrustDidWebError> {
        let mut expected_version_index = 0;
        for entry in &self.did_log_entries {
            expected_version_index += 1;

            if entry.version.index != expected_version_index {
                if expected_version_index == 1 {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Invalid did log. First entry has to have version id 1".to_string(),
                    ));
                } else {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                        "Invalid did log for version {}. Version id has to be incremented",
                        entry.version.index,
                    )));
                }
            }

            // Verify data integrity proof
            entry.verify_data_integrity_proof()?;

            // Verify the entryHash
            entry.verify_version_id_integrity()?;

            if expected_version_index == 1 {
                // Verify that the SCID is correct
                let scid = match entry.parameters.scid.clone() {
                    Some(scid_value) => scid_value,
                    None => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Missing SCID inside the DID document.".to_string(),
                        ))
                    }
                };

                if let Some(res) = &scid_to_validate {
                    if res.ne(scid.as_str()) {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                                        "The SCID '{scid}' supplied inside the DID document does not match the one supplied for validation: '{res}'"
                                    )));
                    }
                }

                let original_scid = entry.build_original_scid(&scid).map_err(|err| {
                    TrustDidWebError::InvalidDataIntegrityProof(format!(
                        "Failed to build original SCID: {err}"
                    ))
                })?;
                if original_scid != scid {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Invalid did log. Genesis entry has invalid SCID".to_string(),
                    ));
                }
            }
        }

        match self.did_log_entries.last() {
            Some(entry) => Ok(entry.clone().did_doc.into()),
            None => Err(TrustDidWebError::InvalidDataIntegrityProof(
                "Invalid did log. No entries found".to_string(),
            )),
        }
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate(&self) -> Result<Arc<DidDoc>, TrustDidWebError> {
        self.validate_with_scid(None)
    }
}

impl std::fmt::Display for DidDocumentState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut log = String::new();
        for entry in &self.did_log_entries {
            let log_line = entry.to_log_entry_line().map_err(|_| std::fmt::Error)?;
            let serialized = serde_json::to_string(&log_line).map_err(|_| std::fmt::Error)?;
            log.push_str(serialized.as_str());
            log.push('\n');
        }
        write!(f, "{log}")
    }
}

/// As specified at https://identity.foundation/didwebvh/v1.0/#method-specific-identifier:
///
/// "The did:webvh method-specific identifier contains both the self-certifying identifier (SCID) for the DID,
/// and a fully qualified domain name (with an optional path) that is secured by a TLS/SSL certificate."
pub struct TrustDidWebId {
    scid: String,
    url: String,
}

static HAS_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap());
static HAS_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\:[0-9]+").unwrap());

impl TrustDidWebId {
    pub const DID_METHOD_NAME: &'static str = "webvh";

    /// Yet another UniFFI-compliant method.
    ///
    /// Otherwise, the idiomatic counterpart (try_from(did_webvh: String) -> Result<Self, Self::Error>) may be used as well.
    pub fn parse_did_webvh(did_webvh: String) -> Result<Self, TrustDidWebIdResolutionError> {
        match Self::try_from(did_webvh) {
            Ok(parsed) => Ok(parsed),
            Err(e) => Err(e),
        }
    }

    pub fn get_scid(&self) -> String {
        self.scid.clone()
    }

    pub fn get_url(&self) -> String {
        self.url.clone()
    }
}

/// Implementation for a string denoting did_webvh
impl TryFrom<String> for TrustDidWebId {
    type Error = TrustDidWebIdResolutionError;

    /// It basically implements the 'The DID to HTTPS Transformation',
    /// as specified by https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
    fn try_from(did_webvh: String) -> Result<Self, Self::Error> {
        let did_webvh_split: Vec<&str> = did_webvh.splitn(4, ":").collect();
        if did_webvh_split.len() < 4 {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_webvh,
            ));
        };

        let method_name = format!("{}:{}", did_webvh_split[0], did_webvh_split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };

        let scid = did_webvh_split[2];
        if scid.is_empty() {
            // the SCID MUST be present in the DID string
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("Empty self-certifying identifier (SCID) detected. An object identifier derived from initial data is expected"),
            ));
        };

        if did_webvh_split[3].replace(":", "").is_empty() || did_webvh_split[3].starts_with(":") {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("No fully qualified domain detected"),
            ));
        };

        // 1. Remove the ‘did:webvh:’ prefix from the input identifier.
        // 2. Remove the SCID segment, which is the first segment after the prefix.
        // 3. Transform the domain segment, the first segment (up to the first ':' character) of the remaining string.
        let url_split: Vec<&str> = did_webvh_split[3].splitn(2, ":").collect();
        // if the domain segment contains a port, decode percent-encoding and preserve the port.
        let domain = url_split[0].replace("%3A", ":"); //.nfc().collect::<String>();
                                                       // 4. Transform the path, the 0 or more segments after the first : character, delimited by : characters.
        let path = if url_split.len() > 1 {
            url_split[1].replace(":", "/")
        } else {
            // if no path segments exist, path becomes '.well-known'
            ".well-known".to_string()
        };

        // 5. Reconstruct the HTTPS URL
        let url_string = format!("https://{domain}/{path}");
        let mut url = match Url::parse(&url_string) {
            Ok(url) => url,
            Err(err) => {
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    format!("Not a valid URL: {err}"),
                ))
            }
        };

        // append '/did.jsonl' to complete the URL.
        match url.path_segments_mut() {
            Ok(mut path_segments) => {
                // 7. Append /did.jsonl to complete the URL.
                path_segments.push("did.jsonl");
            }
            Err(_) => {
                // path_segments_mut "Return Err(()) if this URL is cannot-be-a-base."
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    "This URL cannot-be-a-base".to_string(),
                ));
            }
        };

        Ok(Self {
            scid: scid.to_string(),
            url: url.to_string(),
        })
    }
}

/// Implementation for a tuple denoting did_webvh and allow_http.
#[diagnostic::do_not_recommend]
impl TryFrom<(String, Option<bool>)> for TrustDidWebId {
    type Error = TrustDidWebIdResolutionError;

    fn try_from(value: (String, Option<bool>)) -> Result<Self, Self::Error> {
        let did_webvh = value.0;
        let allow_http = value.1;

        let split: Vec<&str> = did_webvh.splitn(3, ":").collect();
        if split.len() < 3 || split[2].is_empty() {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_webvh,
            ));
        };

        let method_name = format!("{}:{}", split[0], split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };
        let scid = split[2];

        let mut decoded_url = String::from("");
        match scid.split_once(":") {
            Some((scid, did_webvh_reduced)) => {
                url_escape::decode_to_string(did_webvh_reduced.replace(":", "/"), &mut decoded_url);
                let url = match String::from_utf8(decoded_url.into_bytes()) {
                    Ok(url) => {
                        if url.starts_with("localhost")
                            || url.starts_with("127.0.0.1")
                            || allow_http.unwrap_or(false)
                        {
                            format!("http://{url}")
                        } else {
                            format!("https://{url}")
                        }
                    }
                    Err(_) => {
                        return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                            did_webvh_reduced.to_string(),
                        ))
                    }
                };
                if HAS_PATH_REGEX.captures(url.as_str()).is_some()
                    || HAS_PORT_REGEX.captures(url.as_str()).is_some()
                {
                    Ok(Self {
                        scid: scid.to_string(),
                        url: format!("{url}/did.jsonl"),
                    })
                } else {
                    Ok(Self {
                        scid: scid.to_string(),
                        url: format!("{url}/.well-known/did.jsonl"),
                    })
                }
            }
            None => Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_webvh,
            )),
        }
    }
}

pub struct TrustDidWeb {
    did: String,
    did_log: String,
    did_doc: String,
}

impl TrustDidWeb {
    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    pub fn get_did_log(&self) -> String {
        self.did_log.clone()
    }

    pub fn get_did_doc(&self) -> String {
        self.did_doc.clone()
    }

    /// Yet another UniFFI-compliant method.
    pub fn get_did_doc_obj(&self) -> Result<Arc<DidDoc>, TrustDidWebError> {
        let did_doc_json = self.did_doc.clone();
        match json_from_str::<DidDoc>(&did_doc_json) {
            Ok(doc) => Ok(doc.into()),
            Err(e) => Err(TrustDidWebError::DeserializationFailed(e.to_string())),
        }
    }

    /// A UniFFI-compliant constructor.
    pub fn read(did_webvh: String, did_log: String) -> Result<Self, TrustDidWebError> {
        // according to https://identity.foundation/didwebvh/v1.0/#read-resolve
        // parse did logs
        let did_doc_state = DidDocumentState::from(did_log)?;
        // 1. DID-to-HTTPS Transformation
        let did = TrustDidWebId::parse_did_webvh(did_webvh.to_owned())
            .map_err(|err| TrustDidWebError::InvalidMethodSpecificId(format!("{err}")))?;
        let scid = did.get_scid();

        let did_doc_arc = did_doc_state.validate_with_scid(Some(scid.to_owned()))?;
        let did_doc = did_doc_arc.as_ref().clone();
        let did_doc_str = match serde_json::to_string(&did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string())),
        };
        Ok(Self {
            did: did_doc.id,
            did_log: did_doc_state.to_string(), // DidDocumentState implements std::fmt::Display trait
            did_doc: did_doc_str,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::did_webvh::{DidDocumentState, TrustDidWeb};
    use crate::errors::TrustDidWebErrorKind;
    use crate::test::assert_trust_did_web_error;
    use rstest::rstest;
    use std::fs;
    use std::path::Path;

    #[rstest]
    // doc needs to be an object
    #[case("[1,2,3,4,5]", "is not of type \"object\"")]
    // invalid version Id
    #[case(
        r#"{"versionId":"","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{}}"#,
        "does not match"
    )]
    #[case(
        r#"{"versionId":"1","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{}}"#,
        "\"1\" does not match"
    )]
    #[case(
        r#"{"versionId":"hash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{}}"#,
        "\"hash\" does not match"
    )]
    // invalid time
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"", "parameters":{}, "state":{}}"#,
        "Datetime not in ISO8601 format"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"invalid time", "parameters":{}, "state":{}}"#,
        "Datetime not in ISO8601 format"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29 17:15:59", "parameters":{}, "state":{}}"#,
        "Datetime not in ISO8601 format"
    )]
    // invalid state
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"]} }"#,
        "\"id\" is a required property"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"id":""}}"#,
        "\"@context\" is a required property"
    )]
    // did doc context needs to be filled
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":[], "id":""} }"#,
        "[] is not valid under any of the schemas listed in the 'anyOf' keyword"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://www.w3.org/ns/did/v1"], "id":""} }"#,
        "] is not valid under any of the schemas listed in the 'anyOf' keyword"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://w3id.org/security/jwk/v1"], "id":""} }"#,
        "] is not valid under any of the schemas listed in the 'anyOf' keyword"
    )]
    // empty parameters
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"], "id":"did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T05:43:17Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z3L7j2siRiZ4zziQQmRqLY5qH2RfVz6VTC5gbDE6vntw1De5Ej5DNR3wDU6m9KRiUYPm9o8P89yMzNk5EhWVTo4Tn" } ] }"#,
        "Missing DID Document parameters"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{"invalidParameter": 1}, "state":{"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"], "id":"did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"} }"#,
        "Additional properties are not allowed ('invalidParameter' was unexpected)"
    )]
    // invalid proof
    fn test_invalid_did_log(
        #[case] input_str: String,
        #[case] error_string: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_trust_did_web_error(
            DidDocumentState::from(input_str),
            TrustDidWebErrorKind::DeserializationFailed,
            error_string,
        );
        Ok(())
    }

    // /* TODO create new test cases for v1.0
    #[rstest]
    #[case(
            "test_data/manually_created/unhappy_path/invalid_scid.jsonl",
            "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            TrustDidWebErrorKind::InvalidIntegrityProof,
            "invalid DID log integration proof: The SCID"
        )]
    #[case(
        "test_data/manually_created/unhappy_path/signed_with_unauthorized_key.jsonl",
        "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        TrustDidWebErrorKind::InvalidIntegrityProof,
        "Key extracted from proof is not authorized for update"
    )]
    /*
    #[case(
            "test_data/manually_created/unhappy_path/invalid_scid.jsonl",
            "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            TrustDidWebErrorKind::DeserializationFailed,
            "`versionTime` must be greater then the `versionTime` of the previous entry"
        )]
    #[case(
            "test_data/generated_by_didtoolbox_java/unhappy_path/invalid_initial_version_number_did.jsonl",
            "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            TrustDidWebErrorKind::DeserializationFailed,
            "Version numbers (`versionId`) must be in a sequence of positive consecutive integers"
        )]
    #[case(
            "test_data/generated_by_didtoolbox_java/unhappy_path/inconsecutive_version_numbers_did.jsonl",
            "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            TrustDidWebErrorKind::DeserializationFailed,
            "Version numbers (`versionId`) must be in a sequence of positive consecutive integers"
        )]
    #[case(
            "test_data/generated_by_didtoolbox_java/unhappy_path/version_time_in_the_future_did.jsonl",
            "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            TrustDidWebErrorKind::DeserializationFailed,
            "must be before the current datetime"
        )]
    */
    /* TODO generate a proper test case data using didtoolbox-java
    #[case(
        "test_data/generated_by_tdw_js/already_deactivated.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com",
        TrustDidWebErrorKind::InvalidDidDocument,
        "This DID document is already deactivated"
    )]
    #[case(
        "test_data/generated_by_tdw_js/unhappy_path/not_authorized.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com",
        TrustDidWebErrorKind::InvalidIntegrityProof,
        "Key extracted from proof is not authorized for update"
    )]
    */
    fn test_read_invalid_did_log(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
        #[case] error_kind: TrustDidWebErrorKind,
        #[case] err_contains_pattern: String,
    ) {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

        // CAUTION No ? operator required here as we want to inspect the expected error
        let webvh = TrustDidWeb::read(did_url.clone(), did_log_raw);

        assert!(webvh.is_err());
        let err = webvh.err();
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.kind(), error_kind);
        assert!(
            err.to_string().contains(&err_contains_pattern),
            "err message should contain '{}', but got '{}'",
            err_contains_pattern,
            err.to_string()
        );
    }
}
