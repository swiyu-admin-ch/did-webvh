// SPDX-License-Identifier: MIT

//! This project implements the following things:
//!
//! - General util structs reused by other libraries of swiyu-admin-ch
//! - DID Web + Verifiable History (did:webvh) as [specified](https://identity.foundation/didwebvh/v1.0/)
//!

extern crate core;

pub mod did_webvh;
pub mod did_webvh_parameters;
pub mod errors;
pub mod did_webvh_jsonschema;

// CAUTION All structs required by UniFFI bindings generator (declared in UDL) MUST also be "used" here
use did_webvh::*;
use did_sidekicks::did_doc::*;
use did_sidekicks::ed25519::*;
use did_sidekicks::did_jsonschema::*;
//use did_sidekicks::vc_data_integrity;
use errors::*;
use did_webvh_jsonschema::*;

uniffi::include_scaffolding!("did_webvh");

#[cfg(test)]
mod test {
    use super::did_webvh::*;
    use did_sidekicks::did_doc::*;
    use did_sidekicks::ed25519::*;
    use did_sidekicks::jcs_sha256_hasher::*;
    use did_sidekicks::multibase::*;
    use crate::errors::*;
    use did_sidekicks::vc_data_integrity::*;
    use chrono::DateTime;
    use core::panic;
    use hex::encode as hex_encode;
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use rstest::{fixture, rstest};
    use serde_json::{json, Value as JsonValue};
    use std::path::Path;
    use std::{fs, vec};

    #[fixture]
    fn unique_base_url() -> String {
        let random_thing: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        format!("https://localhost:8000/{random_thing}")
    }

    #[fixture]
    #[once]
    fn ed25519_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::generate()
    }

    // The first 5 cases come from https://identity.foundation/didwebvh/v1.0/#example-3
    #[rstest]
    #[case( // domain/did:web-compatible
        "did:webvh:{SCID}:example.com",
        "https://example.com/.well-known/did.jsonl"
    )]
    #[case( // subdomain
        "did:webvh:{SCID}:issuer.example.com",
        "https://issuer.example.com/.well-known/did.jsonl"
    )]
    #[case( // path
        "did:webvh:{SCID}:example.com:dids:issuer",
        "https://example.com/dids/issuer/did.jsonl"
    )]
    #[case( // path with port
        "did:webvh:{SCID}:example.com%3A3000:dids:issuer",
        "https://example.com:3000/dids/issuer/did.jsonl"
    )]
    #[case( // internationalized domain
        "did:webvh:{SCID}:jp納豆.例.jp:用户",
        "https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl"
    )]
    #[case(
        "did:webvh:QMySCID:localhost%3A8000:123:456",
        "https://localhost:8000/123/456/did.jsonl"
    )]
    #[case(
        "did:webvh:QMySCID:localhost%3A8000",
        "https://localhost:8000/.well-known/did.jsonl"
    )]
    #[case("did:webvh:QMySCID:localhost", "https://localhost/.well-known/did.jsonl")]
    #[case(
        "did:webvh:QMySCID:admin.ch%3A8000:123:456",
        "https://admin.ch:8000/123/456/did.jsonl"
    )]
    #[case(
        "did:webvh:QMySCID:admin.ch%3A8000",
        "https://admin.ch:8000/.well-known/did.jsonl"
    )]
    #[case("did:webvh:QMySCID:admin.ch", "https://admin.ch/.well-known/did.jsonl")]
    #[case(
        "did:webvh:QMySCID:sub.admin.ch",
        "https://sub.admin.ch/.well-known/did.jsonl"
    )]
    #[case(
        "did:webvh:QMySCID:sub.admin.ch:mypath:mytrala",
        "https://sub.admin.ch/mypath/mytrala/did.jsonl"
    )]
    #[case("did:webvh:QMySCID:localhost:%2A", "https://localhost/%2A/did.jsonl")]
    #[case(
        "did:webvh:QMySCID:localhost:.hidden",
        "https://localhost/.hidden/did.jsonl"
    )]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let tdw = TrustDidWebId::parse_did_webvh(tdw).unwrap();
        let resolved_url = tdw.get_url();
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("did:xyz:QMySCID:localhost%3A8000:123:456")]
    #[case("did:tdw:QMySCID:localhost%3A8000:123:456")]
    #[case("url:webvh:QMySCID:localhost%3A8000:123:456")]
    fn test_tdw_to_url_conversion_error_kind_method_not_supported(#[case] tdw: String) {
        match TrustDidWebId::parse_did_webvh(tdw) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
            _ => panic!(
                "Expected error kind: {:?}",
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
        }
    }

    #[rstest]
    #[case("did:webvh")] // method only
    #[case("did:webvh::")] // method only
    #[case("did:webvh:::")] // method only
    #[case("did:webvh::::")] // method only
    #[case("did:webvh:SCID")] // no fully qualified domain
    #[case("did:webvh:SCID:::")] // no fully qualified domain
    #[case("did:webvh:SCID::123:")] // no fully qualified domain
    #[case("did:webvh::localhost%3A8000:123:456")] // empty/missing SCID
    fn test_tdw_to_url_conversion_error_kind_invalid_method_specific_id(#[case] tdw: String) {
        match TrustDidWebId::parse_did_webvh(tdw) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
            _ => panic!(
                "Expected error kind: {:?}",
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
        }
    }
//
//    #[rstest]
//    fn test_key_pair_multibase_conversion(
//        ed25519_key_pair: &Ed25519KeyPair, // fixture
//    ) -> Result<(), Box<dyn std::error::Error>> {
//        let original_private = ed25519_key_pair.get_signing_key();
//        let original_public = ed25519_key_pair.get_verifying_key();
//
//        let new_private = Ed25519SigningKey::from_multibase(&original_private.to_multibase())?;
//        let new_public = Ed25519VerifyingKey::from_multibase(&original_public.to_multibase())?;
//
//        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
//        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
//        Ok(())
//    }
//
//    #[rstest]
//    fn test_key_pair_creation_from_multibase(
//        ed25519_key_pair: &Ed25519KeyPair, // fixture
//    ) -> Result<(), Box<dyn std::error::Error>> {
//        let new_ed25519_key_pair =
//            Ed25519KeyPair::from(&ed25519_key_pair.get_signing_key().to_multibase())?;
//
//        assert_eq!(ed25519_key_pair, &new_ed25519_key_pair);
//        assert_eq!(
//            ed25519_key_pair.get_signing_key().to_multibase(),
//            new_ed25519_key_pair.signing_key.to_multibase()
//        );
//        assert_eq!(
//            ed25519_key_pair.get_verifying_key().to_multibase(),
//            new_ed25519_key_pair.verifying_key.to_multibase()
//        );
//        Ok(())
//    }
//
    /// A rather trivial assertion helper around TrustDidWebError.
    pub fn assert_trust_did_web_error<T>(
        res: Result<T, TrustDidWebError>,
        expected_kind: TrustDidWebErrorKind,
        error_contains: &str,
    ) {
        assert!(res.is_err());
        let err = res.err();
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.kind(), expected_kind);

        let err_to_string = err.to_string();
        assert!(
            err_to_string.contains(error_contains),
            "expected '{}' is not mentioned in '{}'",
            error_contains,
            err_to_string
        );
    }

    #[rstest]
    fn test_cryptosuite_add_and_verify_proof() -> Result<(), Box<dyn std::error::Error>> {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
        let credential_without_proof = json!(
            {
                 "@context": [
                     "https://www.w3.org/ns/credentials/v2",
                     "https://www.w3.org/ns/credentials/examples/v2"
                 ],
                 "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
                 "type": ["VerifiableCredential", "AlumniCredential"],
                 "name": "Alumni Credential",
                 "description": "A minimum viable example of an Alumni Credential.",
                 "issuer": "https://vc.example/issuers/5678",
                 "validFrom": "2023-01-01T00:00:00Z",
                 "credentialSubject": {
                     "id": "did:example:abcdefgh",
                     "alumniOf": "The School of Examples"
                 }
            }
        );

        let scid = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&credential_without_proof)
            .unwrap();

        // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
        let options = CryptoSuiteProofOptions::new(
            None,
            Some(DateTime::parse_from_rfc3339("2023-02-24T23:36:38Z").unwrap().to_utc()),
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_string(),
            Some("assertionMethod".to_string()),
            Some(vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://www.w3.org/ns/credentials/examples/v2".to_string(),
            ]),
            format!("1-{}", scid),
        );

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        let suite = did_sidekicks::vc_data_integrity::EddsaJcs2022Cryptosuite {
            verifying_key: Some(Ed25519VerifyingKey::from_multibase(
                "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            )?),
            signing_key: Some(Ed25519SigningKey::from_multibase(
                "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
            )?),
        };

        let secured_document = suite.add_proof(&credential_without_proof, &options)?;

        assert!(
            !secured_document.is_null(),
            "'add_proof' method returned Value::Null"
        );
        let proof = &secured_document["proof"];
        assert!(proof.is_array(), "'proof' must be a JSON array");
        let proof_value = &proof[0]["proofValue"];
        assert!(proof_value.is_string(), "'proofValue' must be a string");

        // https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
        // CAUTION The value suggested in the spec (z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX)
        //         is irrelevant here since the add_proof method also computes a proof's challenge (if not supplied already)
        assert!(proof_value.to_string().contains("z3swhrb2DFocc562PATcKiv8YtjUzxLdfr4dhb9DidvG2BNkJqAXe65bsEMiNJdGKDdnYxiBa7cKXXw4cSKCvMcfm"));

        let doc_hash = JcsSha256Hasher::default().encode_hex(&credential_without_proof)?;
        // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assert_eq!(
            "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
            doc_hash
        );

        // sanity check
        let proof_as_string = serde_json::to_string(proof)?;
        let data_integrity_proof = DataIntegrityProof::from(proof_as_string)?;
        assert!(
            suite.verify_proof(&data_integrity_proof, &doc_hash).is_ok(),
            "Sanity check failed"
        );

        Ok(())
    }

    /* TODO update test for version 1.0
    #[rstest]
    #[case("test_data/generated_by_didtoolbox_java/v010_did.jsonl")]
    #[case("test_data/generated_by_didtoolbox_java/v_0_3_eid_conform/did_doc_without_controller.jsonl")]
    //#[case("test_data/generated_by_tdw_js/unique_update_keys.jsonl")]
    fn test_generate_version_id(
        #[case] did_log_raw_filepath: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;
        let did_document = DidDocumentState::from(did_log_raw)?;
        for did_log in did_document.did_log_entries {
            let hash = did_log.calculate_entry_hash()?;
            assert!(hash == did_log.version.hash);
        }
        Ok(())
    }
    */

    /* TODO update tests to V1.0
    #[rstest]
    /* TODO cleanup and add more test cases 
    #[case(
        "test_data/generated_by_tdw_js/single_update_key.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    #[case(
        "test_data/generated_by_tdw_js/unique_update_keys.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    #[case(
        "test_data/generated_by_tdw_js/alternate_update_keys.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    */
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.0.0-RC1.jsonl",
        "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.0.0.jsonl",
        "did:tdw:Qmb95hd5nGZvJY3q6mGcmZrLTNYMmzJYuMx94VNFb27oi9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.1.0.jsonl",
        "did:tdw:QmVZsmZqj1pGqqdzDeKLwBWZXo5aDucFsYddw9fKPb7e5Z:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.2.0.jsonl",
        "did:tdw:QmX4MSeKo17fvrZQbkHSB4BfkEtJXiGhnbnSAu6oCMYtub:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.3.0.jsonl",
        "did:tdw:Qmdjf4BZUtYnNKWbL5Lj9MqTeqxq5UQBbgU3p5wriwTzDV:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.3.1.jsonl",
        "did:tdw:QmWroVHz78FM6ugJ6MkaD4yu2ihkKmWFiKDcDPXu1AeS1d:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.4.0.jsonl",
        "did:tdw:QmSTru6WjboQ24pVdK21AuX4rV6CEqQSjFQKANaXwGM6wz:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.4.1.jsonl",
        "did:tdw:QmU8WbF9dMzTMU1snugNConzA4tHvPaXRqzyjXn77pUY8G:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/v_0_3_eid_conform/did_doc_without_controller.jsonl",
        "did:tdw:QmZf4Pb1GoPdYaZBF3Sc1nVspXef4qc816C7eBzzuXMoGk:domain.com%3A8080:path1:path2"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/v400_did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_read_did_webvh(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;

        // Read the newly did doc
        let webvh_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw)?;
        let did_doc_v1: JsonValue = serde_json::from_str(&webvh_v1.get_did_doc())?;
        let did_doc_obj_v1 = DidDoc::from_json(&webvh_v1.get_did_doc())?;

        assert!(!did_doc_v1["@context"].to_string().is_empty());
        match did_doc_v1["id"] {
            JsonValue::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()))
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, webvh_v1.get_did());
        assert!(!did_doc_obj_v1.verification_method.is_empty());
        assert!(!did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());

        Ok(())
    }
    */

    /* TODO implement the test case using proper input
    #[rstest]
    #[case(
        "test_data/generated_by_tdw_js/deactivated.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    fn test_read_did_webvh_deactivated(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        //let did_log_raw_filepath = "test_data/generated_by_tdw_js/deactivated.jsonl";
        //let did_url: String = String::from("did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com");

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw)?;
        let did_doc_json_v1: JsonValue = serde_json::from_str(&tdw_v1.get_did_doc())?;
        let did_doc_obj_v1 = DidDoc::from_json(&tdw_v1.get_did_doc())?;

        assert!(!did_doc_json_v1["@context"].to_string().is_empty());
        match did_doc_json_v1["id"] {
            JsonValue::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()), "DID mismatch")
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_json_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_json_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_json_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, tdw_v1.get_did());
        // CAUTION after deactivation these should be empty
        assert!(did_doc_obj_v1.verification_method.is_empty());
        assert!(did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());

        Ok(())
    }
     */
}
