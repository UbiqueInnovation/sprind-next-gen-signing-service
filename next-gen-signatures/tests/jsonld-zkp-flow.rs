use std::{collections::HashMap, time::SystemTime};

use ark_bls12_381::Bls12_381;
use chrono::{DateTime, Months, Utc};
use legogroth16::circom::{CircomCircuit, R1CS as R1CSOrig};
use multibase::Base;
use next_gen_signatures::rdf::RdfQuery;
use oxrdf::{GraphName, NamedNode, Term};
use rand::prelude::*;
use rdf_proofs::{ark_to_base64url, CircuitString, KeyPairBase58Btc, VerifiableCredential};
use rdf_types::generator;
use serde_json::json;

pub type R1CS = R1CSOrig<Bls12_381>;

#[tokio::test]
async fn json_ld_flow() {
    // The test considers the following flow:
    //
    // There existins a person with the following PID:
    // {
    //    "name": "...",
    //    "birthDate": "...",
    // .  "telephone": "..."
    // }
    //
    // A verifier would like to know the name of the person
    // and that the person is born before 2000-01-01.
    let mut rng = StdRng::seed_from_u64(1337);

    let credential = json!({
        "@type": "http://schema.org/Person",
        "id": "did:example:johndoe",
        "http://schema.org/name": "John Doe",
        "http://schema.org/birthDate": {
            "@value": "1990-01-01T00:00:00Z",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "http://schema.org/telephone": "(425) 123-4567",
    });

    // publicly known issuer data
    let issuer_id = "did:example:issuer0";
    let issuer_key_id = format!("{issuer_id}#bls12_381-g2-pub001");

    // issuance of a verifiable credential
    let (_issuer_pk, vc) = {
        let issuer_kp = KeyPairBase58Btc::new(&mut rng).unwrap();
        let issuer_pk = issuer_kp.public_key;

        // public information about the issuer
        let issuer = RdfQuery::from_jsonld(
            &json!(
                {
                    "@context": [
                        "https://www.w3.org/ns/controller/v1",
                        "https://w3id.org/security/data-integrity/v2"
                    ],
                    "id": "did:example:issuer0",
                    "type": "Controller",
                    "verificationMethod": {
                        "id": "did:example:issuer0#bls12_381-g2-pub001",
                        "type": "Multikey",
                        "controller": "did:example:issuer0",
                        "publicKeyMultibase": issuer_pk
                    }
                }
            )
            .to_string(),
            Some("b".to_string()),
        )
        .await
        .unwrap();

        // issuance of a verifiable credential
        let vc = {
            let issuer_sk = issuer_kp.secret_key;

            let issuer = RdfQuery::from_jsonld(
                &json!(
                    {
                        "@context": [
                            "https://www.w3.org/ns/controller/v1",
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
                .checked_add_months(Months::new(36))
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
                    "credentialSubject": credential
                })
                .to_string(),
                Some("b".to_string()),
            )
            .await
            .unwrap();

            let proof_cfg = RdfQuery::from_jsonld(
                &json!(
                    {
                        "@context": "https://www.w3.org/ns/data-integrity/v1",
                        "type": "DataIntegrityProof",
                        "created": now,
                        "cryptosuite": "bbs-termwise-signature-2023",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": issuer_key_id
                    }
                )
                .to_string(),
                Some("b".to_string()),
            )
            .await
            .unwrap();

            let mut vc = VerifiableCredential::new(
                data.as_graph(GraphName::DefaultGraph),
                proof_cfg.as_graph(GraphName::DefaultGraph),
            );
            rdf_proofs::sign(
                &mut rng,
                &mut vc,
                &issuer.as_graph(GraphName::DefaultGraph).into(),
            )
            .expect("Failed to sign vc!");

            vc
        };

        (issuer, vc)
    };

    // predicates provided by the verifier.
    // circuits maybe provided by the verifier
    //   or alternatively publicly defined.
    //   What is important that we know the proving
    //   snark key, which is currently stored in
    //   the circuits map.
    // verifying_key used later to verify the proof.
    // variable is the placeholder for the variable the
    //   the proof is over.
    let (_predicates, _circuits, _verifying_key, _variable) = {
        let verify_date = "2000-01-01T00:00:00Z";
        let verify_var = "to:be:verified";

        let predicates = json!({
            "@context": {
                "circuit": "https://zkp-ld.org/security#circuit",
                "private": "https://zkp-ld.org/security#private",
                "public": "https://zkp-ld.org/security#public",
                "first": "http://www.w3.org/1999/02/22-rdf-syntax-ns#first",
                "rest": "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest",
                "var": "https://zkp-ld.org/security#var",
                "val": "https://zkp-ld.org/security#val"
            },
            "@type": "https://zkp-ld.org/security#Predicate",
            "circuit": {
                "@id": "https://zkp-ld.org/circuit/alexey/lessThanPublic"
            },
            "private": {
                "first": {
                    "@type": "https://zkp-ld.org/security#PrivateVariable",
                    "var": "a",
                    "val": { "@id": verify_var }
                },
                "rest": { "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil" }
            },
            "public": {
                "first": {
                    "@type": "https://zkp-ld.org/security#PublicVariable",
                    "var": "b",
                    "val": {
                        // NOTE: Here is the important bit:
                        "@value": verify_date,
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                    }
                },
                "rest": { "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil" }
            }
        });

        // define circuit
        let circuit_r1cs = R1CS::from_file("circom/bls12381/less_than_public_64.r1cs").unwrap();
        let circuit_wasm = std::fs::read("circom/bls12381/less_than_public_64.wasm").unwrap();
        let commit_witness_count = 1;
        let snark_proving_key = CircomCircuit::setup(circuit_r1cs.clone())
            .generate_proving_key(commit_witness_count, &mut rng)
            .unwrap();

        // serialize to multibase
        let circuit_r1cs = ark_to_base64url(&circuit_r1cs).unwrap();
        let circuit_wasm = multibase::encode(Base::Base64Url, circuit_wasm);
        let snark_proving_key_string = ark_to_base64url(&snark_proving_key).unwrap();
        let snark_verifying_key_string = ark_to_base64url(&snark_proving_key.vk).unwrap();

        let circuits = HashMap::from([(
            "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
            CircuitString {
                circuit_r1cs,
                circuit_wasm,
                snark_proving_key: snark_proving_key_string,
            },
        )]);

        (predicates, circuits, snark_verifying_key_string, verify_var)
    };

    let _ = {
        let mut gen = generator::Blank::new_with_prefix("e".to_string());
        let b_id = gen.next_blank_id().to_string();
        let b_birthdate = gen.next_blank_id().to_string();
        let b_telephone = gen.next_blank_id().to_string();

        let doc = RdfQuery::new(&vc.document.to_string()).unwrap();

        let x = doc.get(
            None,
            NamedNode::new("https://www.w3.org/2018/credentials#credentialSubject").unwrap(),
        );
        println!("{:#?}", x);

        let mut vc_json = RdfQuery::new(&vc.document.to_string()).unwrap().to_json(
            None,
            Some(vec![Term::NamedNode(
                NamedNode::new("https://www.w3.org/2018/credentials#VerifiableCredential").unwrap(),
            )]),
            None,
        );

        let o_id = vc_json["https://www.w3.org/2018/credentials#credentialSubject"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let o_birthdate = vc_json["https://www.w3.org/2018/credentials#credentialSubject"]
            ["http://schema.org/birthDate"]
            .as_str()
            .unwrap()
            .to_string();
        let o_telephone = vc_json["https://www.w3.org/2018/credentials#credentialSubject"]
            ["http://schema.org/telephone"]
            .as_str()
            .unwrap()
            .to_string();

        vc_json["https://www.w3.org/2018/credentials#credentialSubject"]["id"] = json!(b_id);
        vc_json["https://www.w3.org/2018/credentials#credentialSubject"]
            ["http://schema.org/birthDate"] = json!(b_birthdate);
        vc_json["https://www.w3.org/2018/credentials#credentialSubject"]
            ["http://schema.org/telephone"] = json!(b_telephone);

        let deanon_map = HashMap::from([
            (b_id, o_id),
            (b_birthdate, o_birthdate),
            (b_telephone, o_telephone),
        ]);

        println!("{:#?}", deanon_map)
    };
}
