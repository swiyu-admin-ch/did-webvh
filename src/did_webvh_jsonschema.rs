// SPDX-License-Identifier: MIT

use std::str::from_utf8;

use did_sidekicks::did_jsonschema::*;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "src/embed/jsonschema"]
#[include = "*.json"]
struct DidLogJsonSchemaEmbedFolder;

/// W.r.t. corresponding specification version available at https://identity.foundation/didwebvh
///
/// # CAUTION The single currently supported version is: v0.3
#[derive(Debug, Clone, PartialEq)]
pub enum DidLogEntryJsonSchema {
    /// As defined by https://identity.foundation/didwebvh/v0.3 but w.r.t. (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    V03EidConform,
    /// As (strictly) specified by https://identity.foundation/didwebvh/v0.3
    V03,

    /// As defined by https://identity.foundation/didwebvh/v1.0 but w.r.t. (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    V1_0EidConform,
    /// As (strictly) specified by https://identity.foundation/didwebvh/v1.0
    V1_0,
}

impl DidLogEntryJsonSchema {
    /// As defined by https://identity.foundation/didwebvh/v0.3
    const DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME: &str = "did_log_jsonschema_v_0_3.json";

    /// As defined by https://identity.foundation/didwebvh/v0.3 bzt w.r.t. (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    const DID_LOG_ENTRY_JSONSCHEMA_V_0_3_EID_CONFORM_FILENAME: &str =
        "did_log_jsonschema_v_0_3_eid_conform.json";

    /// As defined by https://identity.foundation/didwebvh/v1.0
    const DID_LOG_ENTRY_JSONSCHEMA_V_1_0_FILENAME: &str = "did_log_jsonschema_v_1_0.json";

    /// As defined by https://identity.foundation/didwebvh/v1.0 but w.r.t. (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    const DID_LOG_ENTRY_JSONSCHEMA_V_1_0_EID_CONFORM_FILENAME: &str =
        "did_log_jsonschema_v_1_0_eid_conform.json";

    /// Converts this type into a corresponding JSON schema in UTF-8 format.
    pub fn as_schema(&self) -> String {
        let file_name = match self {
            // CAUTION This (i.e. unwrap() call) will panic only if file denoted by DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME does not exist
            Self::V03 => Self::DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME,
            Self::V03EidConform => Self::DID_LOG_ENTRY_JSONSCHEMA_V_0_3_EID_CONFORM_FILENAME,
            Self::V1_0 => Self::DID_LOG_ENTRY_JSONSCHEMA_V_1_0_FILENAME,
            Self::V1_0EidConform => Self::DID_LOG_ENTRY_JSONSCHEMA_V_1_0_EID_CONFORM_FILENAME,
        };
        let schema_file = DidLogJsonSchemaEmbedFolder::get(file_name).unwrap();
        // CAUTION This (i.e. unwrap() call) will panic only if file denoted by schema_file is not UTF-8
        from_utf8(schema_file.data.as_ref()).unwrap().to_string()
    }
}

#[cfg(test)]
mod test {
    use crate::did_webvh_jsonschema::{
        DidLogEntryJsonSchema, DidLogEntryValidator, DidLogEntryValidatorErrorKind,
    };
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    // TODO add V1.0 test cases
    // CAUTION V03-specific (happy path) case
    #[case(vec!(DidLogEntryJsonSchema::V03), json!([
        "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "2012-12-12T12:12:12Z",
        {
            "method": "did:tdw:0.3",
            "scid": "QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH",
            "updateKeys": [
              "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
              "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
            ],
            "portable": false,
            "prerotation": false,
            "nextKeyHashes": [],
            "witnesses": [],
            "witnessThreshold": 0,
            "deactivated": false
        },
        {"value": {
            "id": "did:tdw:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "controller": "did:tdw:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "verificationMethod": [{
                "id": "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "controller": "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        }},
        [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],]), true, "")]
    // CAUTION V03EidConform-specific (happy path) case
    #[case(vec!(DidLogEntryJsonSchema::V03EidConform), json!([
        "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "2012-12-12T12:12:12Z",
        {
            "method": "did:tdw:0.3",
            "scid": "QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH",
            "updateKeys": [
              "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
              "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
            ],
            "portable": false,
            "prerotation": false,
            "nextKeyHashes": [],
            "witnesses": [],
            "deactivated": false
        },
        {"value": {
            "id": "did:tdw:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "verificationMethod": [{
                "id": "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        }},
        [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],]), true, "")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!([
        "invalid-version-id",
        "2012-12-12T12:12:12Z",
        {"method": "did:tdw:0.3"},
        {"value": {}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false, "\"invalid-version-id\" does not match \"^[1-9][0-9]*-Q[1-9a-zA-NP-Z]{45,}$\"")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!([
        "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "invalid-version-time",
        {"method": "did:tdw:0.3"},
        {"value": {}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false, "Datetime not in ISO8601 format")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{"":""},{"value":{}},[{"":""}]]), false, "Additional properties are not allowed ('' was unexpected)")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{},{"value":{"id":""}},[{"":""}]]), false, "\"@context\" is a required property")] // params may be empty, but DID doc must be complete
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{},{"value":{}},[{}]]), false, "A DID log entry must include a JSON array of five items")] // proof must not be empty
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["","",{},{},[]]), false, "A DID log entry must include a JSON array of five items")] // all empty
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["","",{},{},[{}]]), false, "A DID log entry must include a JSON array of five items")] // all empty
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["","","","",""]), false, "A DID log entry must include a JSON array of five items")] // all JSON strings
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!([]), false, "A DID log entry must include a JSON array of five items")] // empty array
    fn test_validate_using_schema(
        #[case] schemata: Vec<DidLogEntryJsonSchema>,
        #[case] instance: Value,
        #[case] expected: bool,
        #[case] err_contains_pattern: &str,
    ) {
        //-> Result<(), Box<dyn std::error::Error>> {

        schemata.iter().for_each(|schema| {
            let validator = DidLogEntryValidator::from(schema.as_schema());

            //let is_valid = validator.validate(instance.to_string());
            let is_valid = validator.validate_str(instance.to_string().as_str());

            assert_eq!(expected, is_valid.is_ok());
            assert_eq!(!expected, is_valid.is_err());
            if !expected {
                assert!(is_valid.is_err_and(|err| {
                    assert_eq!(err.kind(), DidLogEntryValidatorErrorKind::ValidationError);
                    assert!(
                        err.to_string().contains(err_contains_pattern),
                        "got: '{}', expected '{}'",
                        err.to_string(),
                        err_contains_pattern
                    );
                    true
                }));
            }
        });

        //Ok(())
    }
}
