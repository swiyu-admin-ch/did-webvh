// SPDX-License-Identifier: MIT

use crate::errors::*;
use did_sidekicks::did_method_parameters::DidMethodParameter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// See https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebVerifiableHistoryDidMethodParameters {
    /// Specifies the did:webvh specification version to be used for processing the DID’s log.
    /// Each acceptable value in turn defines what cryptographic algorithms are permitted for the current and
    /// subsequent DID log entries. An update to the specification version in the middle of a DID Log could introduce new parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub method: Option<String>,

    /// The SCID value for the DID
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scid: Option<String>,

    /// A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
    /// See the Authorized Keys section of this specification for additional details.
    #[serde(default)]
    #[serde(rename = "updateKeys", skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,

    /// A JSON array of strings that are hashes of multikey formatted public keys that MAY be added to the updateKeys list in the next log entry.
    /// At least one entry of nextKeyHashes MUST be added to the next updateKeys list.
    #[serde(default)]
    #[serde(rename = "nextKeyHashes", skip_serializing_if = "Option::is_none")]
    pub next_keys: Option<Vec<String>>,

    /// A JSON object declaring the set of witnesses and threshold number of witness proofs required to update the DID.
    #[serde(default)]
    #[serde(rename = "witnesses", skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<Witness>,

    /// An optional entry whose value is a JSON array containing a list of URLs ([RFC9110]) that have notified the DID Controller that they are willing to watch the DID. See the Watchers section of this specification for more details.
    #[serde(rename = "watchers", default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Vec<String>>,

    /// Indicating if the DID is portable, allowing a DID Controller to control if a DID can be moved, while retaining its SCID and verifiable history.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub portable: Option<bool>,

    /// Indicates whether the DID has been deactivated.
    /// A deactivated DID is no longer subject to updates but remains resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub deactivated: Option<bool>,

    /// Indicates how long, in seconds, a resolver should cache the resolved did:webvh DID before refreshing.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ttl: Option<usize>,
}

impl WebVerifiableHistoryDidMethodParameters {
    pub fn for_genesis_did_doc(scid: String, update_key: String) -> Self {
        WebVerifiableHistoryDidMethodParameters {
            method: Some(String::from(DID_METHOD_PARAMETER_VERSION)),
            scid: Some(scid),
            update_keys: Some(vec![update_key]),
            next_keys: None,
            witnesses: None,
            watchers: None,
            deactivated: None,
            ttl: None,
            portable: Some(false),
        }
    }

    pub fn empty() -> Self {
        WebVerifiableHistoryDidMethodParameters {
            method: None,
            scid: None,
            update_keys: None,
            next_keys: None,
            witnesses: None,
            watchers: None,
            deactivated: None,
            portable: None,
            ttl: None,
        }
    }

    /// Validation against all the criteria described in https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters
    ///
    /// Furthermore, the relevant Swiss profile checks are also taken into account here:
    /// https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
    pub fn validate_initial(&self) -> Result<(), WebVerifiableHistoryError> {
        if let Some(method) = &self.method {
            // This item MAY appear in later DID log entries to indicate that the processing rules
            // for that and later entries have been changed to a different specification version.
            if method != DID_METHOD_PARAMETER_VERSION {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(format!(
                    "Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'"
                )));
            }
        } else {
            // This item MUST appear in the first DID log entry.
            return Err(WebVerifiableHistoryError::InvalidDidParameter(
                "Missing 'method' DID parameter. This item MUST appear in the first DID log entry."
                    .to_string(),
            ));
        }

        if let Some(scid) = &self.scid {
            if scid.is_empty() {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(
                    "Invalid 'scid' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
                ));
            }
        } else {
            return Err(WebVerifiableHistoryError::InvalidDidParameter(
                "Missing 'scid' DID parameter. This item MUST appear in the first DID log entry."
                    .to_string(),
            ));
        }

        if let Some(update_keys) = &self.update_keys {
            if update_keys.is_empty() {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(
                    "Empty 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
                ));
            }
        } else {
            return Err(WebVerifiableHistoryError::InvalidDidParameter(
                "Missing 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
            ));
        }

        // As specified by https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check:
        // - Must be either null or a non-empty list of strings
        // - Must only contain valid base58 strings and valid multikeys
        if let Some(next_keys) = &self.next_keys {
            if next_keys.is_empty() {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(
                    "The 'nextKeyHashes' DID parameter must be either None (omitted) or a non-empty list of strings.".to_string(),
                ));
            }
        }

        // https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check:
        // Witnesses won't be supported as they are not needed from the current point of view.
        // As the DIDs are published on a central base registry the DID controller and the hoster
        // are different actors and the chance that both are compromised is minimized.
        // It would add complexity to the resolving of a DID and the base registry would need to also host did-witness.json file.
        if let Some(witness) = &self.witnesses {
            if witness.threshold > 0 || !witness.witnesses.is_empty() {
                // A witness item in the first DID log entry is used to define the witnesses and necessary threshold for that initial log entry.
                // In all other DID log entries, a witness item becomes active after the publication of its entry.
                return Err(WebVerifiableHistoryError::InvalidDidParameter(
                    "Unsupported non-empty 'witness' DID parameter.".to_string(),
                ));
            }
        }

        /* TODO Ensure validity of the "portable" DID parameter. Currently ignored/disabled for the sake of being able to use test vectors from third parties
        if let Some(portable) = self.portable {
            if portable {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(
                    "Unsupported 'portable' DID parameter. We currently don't support portable DIDs".to_string(),
                ));
            }
        }
         */

        Ok(())
    }

    pub fn merge_from(
        &mut self,
        other: &WebVerifiableHistoryDidMethodParameters,
    ) -> Result<(), WebVerifiableHistoryError> {
        let new_params = other.to_owned();
        let current_params = self.clone();
        self.method = match new_params.method {
            Some(method) => {
                // This item MAY appear in later DID log entries to indicate that the processing rules
                // for that and later entries have been changed to a different specification version.
                if method != DID_METHOD_PARAMETER_VERSION {
                    return Err(WebVerifiableHistoryError::InvalidDidParameter(
                        format!("Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'.")
                    ));
                }
                Some(method)
            }
            None => current_params.method,
        };

        self.scid = match new_params.scid {
            Some(scid) => {
                if current_params.scid.is_none_or(|x| x != scid) {
                    return Err(WebVerifiableHistoryError::InvalidDidParameter(
                        "Invalid 'scid' DID parameter. The 'scid' parameter is not allowed to change."
                        .to_string(),
                    ));
                };
                Some(scid)
            }
            None => self.scid.clone(),
        };

        self.update_keys = new_params.update_keys.or(current_params.update_keys);

        self.next_keys = new_params.next_keys.or(current_params.next_keys);

        self.witnesses = match new_params.witnesses {
            Some(witness) => {
                if witness.threshold > 0 || !witness.witnesses.is_empty() {
                    return Err(WebVerifiableHistoryError::InvalidDidParameter(
                        "Unsupported non-empty 'witnesses' DID parameter.".to_string(),
                    ));
                }
                Some(Witness {
                    threshold: 0,
                    witnesses: vec![],
                })
            }
            None => current_params.witnesses,
        };

        self.watchers = new_params.watchers.or(current_params.watchers);

        self.portable = match (current_params.portable, new_params.portable) {
            (Some(true), Some(true)) => return Err(WebVerifiableHistoryError::InvalidDidParameter(
                "Unsupported 'portable' DID parameter. We currently don't support portable dids".to_string(),
            )),
            (_, Some(true)) =>  return Err(WebVerifiableHistoryError::InvalidDidParameter(
                "Invalid 'portable' DID parameter. The value can ONLY be set to true in the first log entry, the initial version of the DID.".to_string(),
            )),
            (_, Some(false)) => Some(false),
            (_, None) => current_params.portable

        };

        self.deactivated = match (current_params.deactivated, new_params.deactivated) {
            (Some(true), _) => return Err(WebVerifiableHistoryError::InvalidDidDocument(
                "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_string()
            )),
            (_, Some(deactivate)) => Some(deactivate),
            (_, None) => current_params.deactivated,
        };

        self.ttl = new_params.ttl.or(self.ttl.to_owned());

        Ok(())
    }

    /// As specified by https://identity.foundation/didwebvh/v0.3/#deactivate-revoke
    pub fn deactivate(&mut self) {
        self.update_keys = Some(vec![]);
        self.deactivated = Some(true);
    }

    pub fn from_json(json_content: &str) -> Result<Self, WebVerifiableHistoryError> {
        let did_method_parameters: WebVerifiableHistoryDidMethodParameters =
            match serde_json::from_str(json_content) {
                Ok(did_method_parameters) => did_method_parameters,
                Err(err) => {
                    return Err(WebVerifiableHistoryError::DeserializationFailed(format!(
                        "Error parsing DID method parameters: {err}"
                    )));
                }
            };
        Ok(did_method_parameters)
    }

    pub fn get_scid_option(&self) -> Option<String> {
        self.scid.clone()
    }

    /// Yet another UniFFI-compliant getter.
    pub fn get_scid(&self) -> String {
        if let Some(v) = &self.scid {
            return v.clone();
        }
        "".to_string()
    }

    /// Yet another UniFFI-compliant getter.
    pub fn get_update_keys(&self) -> Vec<String> {
        if let Some(v) = &self.update_keys {
            return v.clone();
        }
        vec![]
    }

    /// Yet another UniFFI-compliant getter.
    pub fn is_deactivated(&self) -> bool {
        if let Some(v) = self.deactivated {
            if v {
                return v;
            }
        }
        false
    }
}

impl TryInto<HashMap<String, Arc<DidMethodParameter>>> for WebVerifiableHistoryDidMethodParameters {
    type Error = WebVerifiableHistoryError;

    /// Conversion of [`WebVerifiableHistoryDidMethodParameters`] into map of [`DidMethodParameter`] objects.
    ///
    /// A UniFFI-compliant method.
    fn try_into(self) -> Result<HashMap<String, Arc<DidMethodParameter>>, Self::Error> {
        let params = self.clone();

        // MUST appear in the first DID log entry
        let method = match DidMethodParameter::new_string_from_option("method", params.method) {
            Ok(v) => v,
            Err(err) => {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(format!(
                    "{err}"
                )))
            }
        };

        // MUST appear in the first log entry. MUST NOT appear in later log entries
        let scid = match DidMethodParameter::new_string_from_option("scid", params.scid) {
            Ok(v) => v,
            Err(err) => {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(format!(
                    "{err}"
                )))
            }
        };

        // This property MUST appear in the first log entry and MAY appear in subsequent entries
        let update_keys = match DidMethodParameter::new_string_array_from_option(
            "update_keys",
            params.update_keys,
        ) {
            Ok(v) => v,
            Err(err) => {
                return Err(WebVerifiableHistoryError::InvalidDidParameter(format!(
                    "{err}"
                )))
            }
        };

        Ok(HashMap::from([
            (method.get_name(), Arc::new(method)),
            (scid.get_name(), Arc::new(scid)),
            (update_keys.get_name(), Arc::new(update_keys)),
            // Defaults to false if omitted in the first entry
            (
                "portable".to_string(),
                Arc::new(DidMethodParameter::new_bool_from_option(
                    "portable",
                    params.deactivated,
                )),
            ),
            // Defaults to false if not set in the first DID log entry
            (
                "deactivated".to_string(),
                Arc::new(DidMethodParameter::new_bool_from_option(
                    "deactivated",
                    params.deactivated,
                )),
            ),
            // Defaults to 3600 (1 hour) if not set in the first DID log entry
            (
                "ttl".to_string(),
                Arc::new(
                    DidMethodParameter::new_number_from_option("ttl", params.ttl).unwrap_or_else(
                        |_| DidMethodParameter::new_number_from_option("ttl", Some(3600)).unwrap(),
                    ),
                ),
            ),
        ]))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Witness {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub threshold: u32,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub witnesses: Vec<String>,
}

/// This is only used for serialize
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(num: &u32) -> bool {
    *num == 0
}

/// As defined by https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
const DID_METHOD_PARAMETER_VERSION: &str = "did:webvh:1.0";

#[cfg(test)]
mod test {
    use crate::did_webvh_method_parameters::{
        WebVerifiableHistoryDidMethodParameters, Witness, DID_METHOD_PARAMETER_VERSION,
    };
    use crate::errors::WebVerifiableHistoryErrorKind;
    use crate::test::assert_trust_did_web_error;
    use did_sidekicks::did_method_parameters::DidMethodParameter;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::ops::Deref;
    use std::sync::Arc;

    #[rstest]
    fn test_did_webvh_parameters_validate_initial() {
        let params_for_genesis_did_doc =
            WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
                "scid".to_string(),
                "update_key".to_string(),
            );
        assert!(params_for_genesis_did_doc.validate_initial().is_ok());

        let mut params = params_for_genesis_did_doc.clone();

        // Test "method" DID parameter
        params.method = Some("invalidVersion".to_string());
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        params.method = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Missing 'method' DID parameter.",
        );

        // Test "scid" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.scid = Some("".to_string());
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        params.scid = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Missing 'scid' DID parameter.",
        );

        // Test "update_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.update_keys = Some(vec![]);
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Empty 'updateKeys' DID parameter.",
        );
        params.update_keys = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Missing 'updateKeys' DID parameter.",
        );

        params = params_for_genesis_did_doc.clone();
        /* TODO Test the "portable" DID parameter properly. Currently ignored/disabled for the sake of being able to use test vectors from third parties
        params.portable = Some(true);
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter",
        );
        */
        params.portable = Some(false);
        assert!(params.validate_initial().is_ok());
        params.portable = None;
        assert!(params.validate_initial().is_ok());

        // Test "next_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.next_keys = Some(vec![]);
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "The 'nextKeyHashes' DID parameter must be either None (omitted) or a non-empty list of strings",
        );
        params.next_keys = Some(vec!["some_valid_key".to_string()]);
        assert!(params.validate_initial().is_ok());
        params.next_keys = None;
        assert!(params.validate_initial().is_ok());

        // Test "witnesses" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.witnesses = Some(Witness {
            threshold: 1,
            witnesses: vec!["some_valid_witness".to_string()],
        });
        assert_trust_did_web_error(
            params.validate_initial(),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witness' DID parameter.",
        );
        params.witnesses = Some(Witness {
            threshold: 0,
            witnesses: vec![],
        });
        assert!(params.validate_initial().is_ok());
        params.witnesses = None;
        assert!(params.validate_initial().is_ok());
    }

    #[rstest]
    fn test_did_webvh_parameters_validate_transition() {
        let base_params = WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
            "scid".to_string(),
            "update_key".to_string(),
        );

        let mut old_params = base_params.clone();
        let mut new_params = base_params.clone();
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "method" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.method = Some("invalidVersion".to_string());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        new_params.method = None;
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "scid" DID parameter
        old_params = old_params.clone();
        new_params = new_params.clone();
        new_params.scid = Some("otherSCID".to_string());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        new_params.scid = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.scid = Some("scid".to_string()); // SAME scid value
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "update_keys" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.update_keys = Some(vec!["newUpdateKey".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.update_keys = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.update_keys = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "next_keys" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.next_keys = Some(vec!["newUpdateKeyHash".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.next_keys = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.next_keys = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "witness" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.witnesses = Some(Witness {
            threshold: 1,
            witnesses: vec!["some_valid_witness".to_string()],
        });
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witnesses' DID parameter.",
        );
        new_params.witnesses = Some(Witness {
            threshold: 0,
            witnesses: vec![],
        });
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.witnesses = None;
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test watchers
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.watchers = Some(vec!["https://example.domain".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.watchers = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.watchers = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "portable" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();

        new_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Invalid 'portable' DID parameter.",
        );
        new_params.portable = Some(false);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.portable = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.portable = Some(true);
        old_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            WebVerifiableHistoryErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter.",
        );
    }

    #[rstest]
    fn test_did_webvh_method_parameters_try_into() {
        let mut base_params = WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
            "scid".to_string(),
            "some_update_key".to_string(),
        );
        base_params.portable = Some(true);
        base_params.deactivated = Some(true);
        base_params.ttl = Some(7200);

        let try_into = base_params.try_into(); // MUT

        assert!(try_into.is_ok());
        let param_map: HashMap<String, Arc<DidMethodParameter>> = try_into.unwrap();
        assert!(!param_map.is_empty());

        assert!(param_map.contains_key("method"));
        let method_option = param_map.get("method");
        assert!(method_option.is_some());
        let method = method_option.unwrap();
        assert!(method.is_string());
        assert!(method.get_string_value().is_some());
        assert_eq!(
            DID_METHOD_PARAMETER_VERSION,
            method.get_string_value().unwrap()
        );

        assert!(param_map.contains_key("scid"));
        let scid_option = param_map.get("scid");
        assert!(scid_option.is_some());
        let scid = scid_option.unwrap();
        assert!(scid.is_string());
        assert!(method.get_string_value().is_some());
        assert_eq!("scid", scid.get_string_value().unwrap());

        assert!(param_map.contains_key("update_keys"));
        let update_keys_option = param_map.get("update_keys");
        assert!(update_keys_option.is_some());
        let update_keys = update_keys_option.unwrap();
        assert!(update_keys.is_array());
        assert!(!update_keys.is_empty_array());
        assert!(update_keys.get_string_array_value().is_some());
        assert!(!update_keys.get_string_array_value().unwrap().is_empty());
        assert!(!update_keys
            .get_string_array_value()
            .unwrap()
            .iter()
            .all(|v| v.is_empty()));
        assert!(update_keys
            .get_string_array_value()
            .unwrap()
            .iter()
            .any(|v| v.contains("some_update_key")));

        assert!(param_map.contains_key("portable"));
        let portable_option = param_map.get("portable");
        assert!(portable_option.is_some());
        let portable = portable_option.unwrap();
        assert!(portable.is_bool());
        assert!(portable.get_bool_value().is_some_and(|t| { t == true }));

        assert!(param_map.contains_key("deactivated"));
        let deactivated_option = param_map.get("deactivated");
        assert!(deactivated_option.is_some());
        let deactivated = deactivated_option.unwrap();
        assert!(deactivated.is_bool());
        assert!(deactivated.get_bool_value().is_some_and(|t| { t == true }));

        assert!(param_map.contains_key("ttl"));
        let ttl_option = param_map.get("ttl");
        assert!(ttl_option.is_some());
        let ttl = ttl_option.unwrap();
        assert!(!ttl.is_f64());
        assert!(ttl.is_i64());
        assert!(!ttl.is_u64());
        assert!(ttl.get_f64_value().is_none());
        assert!(ttl.get_i64_value().is_some());
        assert!(ttl.get_u64_value().is_none());
        assert_eq!(7200, ttl.get_i64_value().unwrap());
    }
}
