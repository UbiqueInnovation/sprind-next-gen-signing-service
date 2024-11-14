use std::collections::HashMap;

use oxrdf::{GraphName, NamedNode};
use rand::RngCore;
use rdf_proofs::VcPairString;
use rdf_types::generator;
use serde_json::{json, Value as JsonValue};

use crate::rdf::RdfQuery;

use super::{load_circuits, Credential, Presentation, ProofRequirement};

pub async fn present<R: RngCore>(
    rng: &mut R,
    vc: Credential,
    reqs: &Vec<ProofRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: String,
    issuer_id: &str,
    issuer_key_id: &str,
) -> Presentation {
    let circuits = load_circuits(proving_keys);

    let json = vc.as_json();

    let mut subject = HashMap::<String, JsonValue>::new();
    let mut deanon_map = HashMap::<String, String>::new();
    let mut predicates = Vec::<String>::new();

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
                    "publicKeyMultibase": issuer_pk
                }
            }
        )
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap()
    .to_rdf_string();

    let body = json["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .unwrap();

    let rdf_body = vc
        .graph
        .get_value(
            NamedNode::new_unchecked("https://www.w3.org/2018/credentials#credentialSubject"),
            Some(&vc.graph.get_graph_by_name(GraphName::DefaultGraph)),
        )
        .unwrap()
        .as_graph()
        .unwrap();

    let mut gen = generator::Blank::new_with_prefix("e".to_string());

    for req in reqs {
        let (key, value) = body.iter().find(|(key, _)| req.get_key() == *key).unwrap();

        match req {
            ProofRequirement::Required { .. } => {
                subject.insert(key.clone(), value.clone());
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                public_var,
                public_val,
                ..
            } => {
                let value = rdf_body
                    .get_value(NamedNode::new_unchecked(key), None)
                    .unwrap()
                    .as_value()
                    .unwrap();

                let public_val = serde_json::to_value(public_val).unwrap();

                let blank = deanon_map
                    .iter()
                    .find_map(|(k, v)| (v == &value).then_some(k.clone()))
                    .unwrap_or_else(|| gen.next_blank_id().to_string());

                deanon_map.insert(blank.clone(), value);

                let predicate = json!({
                  "@type": "https://zkp-ld.org/security#Predicate",
                  "https://zkp-ld.org/security#circuit": { "@id": id },
                  "https://zkp-ld.org/security#private": {
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#first": {
                      "@type": "https://zkp-ld.org/security#PrivateVariable",
                      "https://zkp-ld.org/security#val": { "@id": "to:be:verified" },
                      "https://zkp-ld.org/security#var": private_var
                    },
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest": {
                      "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
                    }
                  },
                  "https://zkp-ld.org/security#public": {
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#first": {
                      "@type": "https://zkp-ld.org/security#PublicVariable",
                      "https://zkp-ld.org/security#val": public_val,
                      "https://zkp-ld.org/security#var": public_var
                    },
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest": {
                      "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
                    }
                  }
                });

                let predicate =
                    RdfQuery::from_jsonld(&predicate.to_string(), Some("b".to_string()))
                        .await
                        .unwrap()
                        .to_rdf_string()
                        .replace("<to:be:verified>", &blank);

                predicates.push(predicate);

                subject.insert(key.clone(), json!({ "@id": blank }));
            }
        }
    }

    let disc_vc = {
        let mut disc_vc = json.clone();

        disc_vc["https://www.w3.org/2018/credentials#credentialSubject"] = json!(subject);
        RdfQuery::from_jsonld(&disc_vc.to_string(), Some("e".to_string()))
            .await
            .unwrap()
            .to_rdf_string()
    };

    let vc_pair = VcPairString::new(&vc.rdf_doc, &vc.rdf_proof, &disc_vc, &vc.rdf_proof);

    let proof = rdf_proofs::derive_proof_string(
        rng,
        &vec![vc_pair],
        &deanon_map,
        &issuer,
        None,
        None,
        None,
        None,
        None,
        Some(&predicates),
        Some(&circuits),
    )
    .unwrap();

    Presentation::new(&proof)
}
