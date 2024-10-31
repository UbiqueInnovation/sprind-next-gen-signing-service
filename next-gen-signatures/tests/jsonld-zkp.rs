use std::collections::HashMap;

use ark_bls12_381::Bls12_381;
use legogroth16::circom::{CircomCircuit, R1CS as R1CSOrig};
use multibase::Base;
use next_gen_signatures::rdf::RdfQuery;
use oxrdf::GraphName;
use rand::{prelude::StdRng, SeedableRng};
use rdf_proofs::{
    ark_to_base64url, CircuitString, KeyGraph, KeyPairBase58Btc, VcPairString, VerifiableCredential,
};
use rdf_types::generator;

pub type R1CS = R1CSOrig<Bls12_381>;

#[tokio::test]
async fn jsonld_zkp() {
    let mut rng = StdRng::seed_from_u64(1337);
    let issuer_kp = KeyPairBase58Btc::new(&mut rng).unwrap();
    let issuer_pk = issuer_kp.public_key;
    let issuer_sk = issuer_kp.secret_key;

    let issuer = RdfQuery::from_jsonld(
        &format!(
            r#"
            {{
                "@context": [
                    "https://www.w3.org/ns/controller/v1",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "id": "did:example:issuer0",
                "type": "Controller",
                "verificationMethod": {{
                    "id": "did:example:issuer0#bls12_381-g2-pub001",
                    "type": "Multikey",
                    "controller": "did:example:issuer0",
                    "secretKeyMultibase": "{issuer_sk}",
                    "publicKeyMultibase": "{issuer_pk}"
                }}
            }}"#
        ),
        Some("b".to_string()),
    )
    .await
    .unwrap();
    println!("{}", issuer.to_rdf_string());

    let data = RdfQuery::from_jsonld(
        r#"
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/ns/data-integrity/v1",
                    "https://schema.org/",
                    {
                        "CoolStuff": {
                            "@id": "http://example.org/CoolStuff",
                            "@type": "@id"
                        },
                        "coolNumber": {
                            "@id": "http://example.org/coolNumber",
                            "@type": "@id"
                        }
                    }
                ],
                "id": "http://example.org/credentials/person/0",
                "type": "VerifiableCredential",
                "issuer": "did:example:issuer0",
                "issuanceDate": "2024-01-01T00:00:00Z",
                "expirationDate": "2028-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:coolstuff",
                    "type": "CoolStuff",
                    "coolNumber": 1337
                }
            }"#,
        Some("b".to_string()),
    )
    .await
    .unwrap();
    println!("{}", data.to_rdf_string());

    let proof_config = RdfQuery::from_jsonld(
        r#"
        {
            "@context": "https://www.w3.org/ns/data-integrity/v1",
            "type": "DataIntegrityProof",
            "created": "2024-01-01T12:00:00.000Z",
            "cryptosuite": "bbs-termwise-signature-2023",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:example:issuer0#bls12_381-g2-pub001"
        }"#,
        Some("b".to_string()),
    )
    .await
    .unwrap();
    println!("{}", proof_config.to_rdf_string());

    let key_graph: KeyGraph = issuer.as_graph(GraphName::DefaultGraph).into();

    let mut gen = generator::Blank::new_with_prefix("e".to_string());
    let blank1 = gen.next_blank_id();
    let blank2 = gen.next_blank_id();

    let disc_data = RdfQuery::from_jsonld(
        &format!(
            r#"
            {{
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/ns/data-integrity/v1",
                    "https://schema.org/",
                    {{
                        "CoolStuff": {{
                            "@id": "http://example.org/CoolStuff",
                            "@type": "@id"
                        }},
                        "coolNumber": {{
                            "@id": "http://example.org/coolNumber",
                            "@type": "@id"
                        }}
                    }}
                ],
                "id": "http://example.org/credentials/person/0",
                "type": "VerifiableCredential",
                "issuer": "did:example:issuer0",
                "issuanceDate": "2024-01-01T00:00:00Z",
                "expirationDate": "2028-01-01T00:00:00Z",
                "credentialSubject": {{
                    "@id": "{blank1}",
                    "type": "CoolStuff",
                    "coolNumber": {{
                        "@id": "{blank2}"
                    }}
                }}
        }}"#,
        ),
        Some("e".to_string()),
    )
    .await
    .unwrap();
    println!("{}", disc_data.to_rdf_string());

    let mut vc = VerifiableCredential::new(
        data.as_graph(GraphName::DefaultGraph),
        proof_config.as_graph(GraphName::DefaultGraph),
    );
    rdf_proofs::sign(&mut rng, &mut vc, &key_graph).unwrap();
    let disc_vc = VerifiableCredential::new(
        disc_data.as_graph(GraphName::DefaultGraph),
        vc.proof.clone(),
    );
    println!("{disc_vc}");

    let deanon_map = HashMap::from([
        (blank1.to_string(), "<did:example:coolstuff>".to_string()),
        (
            blank2.to_string(),
            "\"1337\"^^<http://www.w3.org/2001/XMLSchema#integer>".to_string(),
        ),
    ]);
    println!("{deanon_map:#?}");

    let vc_pairs = vec![VcPairString::new(
        &vc.document.clone().to_string(),
        &vc.proof.clone().to_string(),
        &disc_vc.document.clone().to_string(),
        &disc_vc.proof.clone().to_string(),
    )];

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

    let predicates = vec![RdfQuery::from_jsonld(
        r#"
        {
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
                    "val": {
                        "@id": "to:be:verified"
                    }
                },
                "rest": {
                    "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
                }
            },
            "public": {
                "first": {
                    "@type": "https://zkp-ld.org/security#PublicVariable",
                    "var": "b",
                    "val": {
                        "@value": 9999,
                        "@type": "http://www.w3.org/2001/XMLSchema#integer"
                    }
                },
                "rest": {
                    "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
                }
            }
        }"#,
        Some("b".to_string()),
    )
    .await
    .unwrap()
    .to_rdf_string()
    // NOTE: this is a hack
    .replace("<to:be:verified>", blank2.as_ref())];

    println!("{}", predicates[0]);

    let circuits = HashMap::from([(
        "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
        CircuitString {
            circuit_r1cs,
            circuit_wasm,
            snark_proving_key: snark_proving_key_string,
        },
    )]);

    let snark_verifying_keys = HashMap::from([(
        "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
        snark_verifying_key_string,
    )]);

    let proof = rdf_proofs::derive_proof_string(
        &mut rng,
        &vc_pairs,
        &deanon_map,
        &issuer.to_rdf_string(),
        None,
        None,
        None,
        None,
        None,
        Some(&predicates),
        Some(&circuits),
    )
    .unwrap();

    println!("{proof}");

    let success = rdf_proofs::verify_proof_string(
        &mut rng,
        &proof,
        &issuer.to_rdf_string(),
        None,
        None,
        Some(snark_verifying_keys),
    );

    assert!(success.is_ok(), "{success:#?}");
}
