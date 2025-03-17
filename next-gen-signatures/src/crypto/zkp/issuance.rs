use std::time::SystemTime;

use chrono::{DateTime, Months, Utc};
use oxrdf::GraphName;
use rand::RngCore;
use rdf_proofs::VerifiableCredential;
use serde_json::{json, Value as JsonValue};

use crate::rdf::RdfQuery;

use super::{common::get_proof_cfg, Credential};

pub async fn issue<R: RngCore>(
    rng: &mut R,
    data: JsonValue,
    issuer_pk: String,
    issuer_sk: String,
    issuer_id: &str,
    issuer_key_id: &str,
    exp_months: u32,
) -> Credential {
    let issuer = RdfQuery::from_jsonld(
        &json!(
            {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1",
                    "https://w3id.org/security/jwk/v1",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "id": issuer_id,
                "type": "Controller",
                "verificationMethod": {
                    "id": issuer_key_id,
                    "type": "Multikey",
                    "controller": issuer_id,
                    "secretKeyMultibase": issuer_sk,
                    "publicKeyMultibase": issuer_pk
                }
            }
        )
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let now: DateTime<Utc> = SystemTime::now().into();
    let exp = now
        .checked_add_months(Months::new(exp_months))
        .expect("Failed to get expiration date");
    let now = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let exp = exp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let credential_id = "http://example.org/credentials/person/0";

    let data = RdfQuery::from_jsonld(
        &json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/ns/data-integrity/v1"
            ],
            "id": credential_id,
            "type": "VerifiableCredential",
            "issuer": issuer_id,
            "issuanceDate": now,
            "expirationDate": exp,
            "credentialSubject": data
        })
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let proof_cfg = RdfQuery::from_jsonld(
        &get_proof_cfg(issuer_key_id).to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let mut vc = VerifiableCredential::new(
        data.as_graph(GraphName::DefaultGraph),
        proof_cfg.as_graph(GraphName::DefaultGraph),
    );
    rdf_proofs::sign(
        rng,
        &mut vc,
        &issuer.as_graph(GraphName::DefaultGraph).into(),
    )
    .expect("Failed to sign vc!");

    let doc = multibase::encode(multibase::Base::Base64Url, vc.document.to_string());
    let proof = multibase::encode(multibase::Base::Base64Url, vc.proof.to_string());

    Credential::new(&doc, &proof)
}

pub async fn issue_with_device_binding<R: RngCore>(
    rng: &mut R,
    data: JsonValue,
    issuer_pk: String,
    issuer_sk: String,
    issuer_id: &str,
    issuer_key_id: &str,
    exp_months: u32,
    device_binding: (String, String),
) -> Credential {
    let issuer = RdfQuery::from_jsonld(
        &json!(
            {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1",
                    "https://w3id.org/security/jwk/v1",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "id": issuer_id,
                "type": "Controller",
                "verificationMethod": {
                    "id": issuer_key_id,
                    "type": "Multikey",
                    "controller": issuer_id,
                    "secretKeyMultibase": issuer_sk,
                    "publicKeyMultibase": issuer_pk
                }
            }
        )
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let now: DateTime<Utc> = SystemTime::now().into();
    let exp = now
        .checked_add_months(Months::new(exp_months))
        .expect("Failed to get expiration date");
    let now = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let exp = exp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let credential_id = "http://example.org/credentials/person/0";

    let (x, y) = device_binding;

    let data = RdfQuery::from_jsonld(
        &json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/ns/data-integrity/v1"
            ],
            "https://example.org/deviceBinding": {
                "id": "test:device:binding",
                "https://example.org/deviceBinding/x": {
                    "@value": x,
                    "@type": "http://www.w3.org/2001/XMLSchema#hexBinary",
                },
                "https://example.org/deviceBinding/y": {
                    "@value": y,
                    "@type": "http://www.w3.org/2001/XMLSchema#hexBinary",
                },
            },
            "id": credential_id,
            "type": "VerifiableCredential",
            "issuer": issuer_id,
            "issuanceDate": now,
            "expirationDate": exp,
            "credentialSubject": data
        })
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let proof_cfg = RdfQuery::from_jsonld(
        &get_proof_cfg(issuer_key_id).to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let mut vc = VerifiableCredential::new(
        data.as_graph(GraphName::DefaultGraph),
        proof_cfg.as_graph(GraphName::DefaultGraph),
    );
    rdf_proofs::sign(
        rng,
        &mut vc,
        &issuer.as_graph(GraphName::DefaultGraph).into(),
    )
    .expect("Failed to sign vc!");

    let doc = multibase::encode(multibase::Base::Base64Url, vc.document.to_string());
    let proof = multibase::encode(multibase::Base::Base64Url, vc.proof.to_string());

    Credential::new(&doc, &proof)
}
