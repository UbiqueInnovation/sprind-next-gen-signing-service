use std::collections::HashMap;

use crate::rdf::RdfQuery;

use super::{Presentation, ProofRequirement};

use itertools::Itertools;
use oxrdf::{GraphName, NamedNode, Term};
use rand::RngCore;
use serde_json::{json, Value as JsonValue};

pub async fn verify<R: RngCore>(
    rng: &mut R,
    pres: Presentation,
    issuer_pk: String,
    verifying_keys: HashMap<String, String>,
    reqs: &Vec<ProofRequirement>,
    issuer_id: &str,
    issuer_key_id: &str,
) -> JsonValue {
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

    let success = rdf_proofs::verify_proof_string(
        rng,
        &pres.graph.to_rdf_string(),
        &issuer,
        None,
        None,
        Some(verifying_keys),
    );

    assert!(success.is_ok(), "{success:#?}");

    let json = pres.graph.to_json(None, None, None)
        ["https://www.w3.org/2018/credentials#verifiableCredential"]
        .clone();

    let subject = json["https://www.w3.org/2018/credentials#credentialSubject"].clone();

    for req in reqs {
        match req {
            ProofRequirement::Required { key } => {
                assert!(subject.get(key).is_some());
            }
            ProofRequirement::Circuit {
                id,
                private_key,
                private_var,
                public_val,
                public_var,
            } => {
                let blank_id = subject
                    .get(private_key)
                    .unwrap()
                    .get("@id")
                    .unwrap()
                    .as_str()
                    .unwrap();

                let predicate = NamedNode::new_unchecked("https://zkp-ld.org/security#predicate");

                let graphs = pres
                    .graph
                    .quads
                    .iter()
                    .filter_map(|q| (q.predicate == predicate).then_some(q.object.clone()))
                    .dedup()
                    .filter_map(|s| match s {
                        Term::Literal(_) => None,
                        Term::BlankNode(node) => Some(
                            pres.graph
                                .get_graph_by_name(GraphName::BlankNode(node))
                                .to_json(None, None, None),
                        ),
                        Term::NamedNode(node) => Some(
                            pres.graph
                                .get_graph_by_name(GraphName::NamedNode(node))
                                .to_json(None, None, None),
                        ),
                    })
                    .find(|json| {
                        let x = || {
                            let public = json
                                .get("https://zkp-ld.org/security#public")?
                                .get("http://www.w3.org/1999/02/22-rdf-syntax-ns#first")?;
                            let pub_val = public
                                .get("https://zkp-ld.org/security#val")?
                                .get("@value")?;
                            let pub_type = public
                                .get("https://zkp-ld.org/security#val")?
                                .get("@type")?;
                            let pub_var = public
                                .get("https://zkp-ld.org/security#var")?
                                .get("@value")?;

                            let priv_var = json
                                .get("https://zkp-ld.org/security#private")?
                                .get("http://www.w3.org/1999/02/22-rdf-syntax-ns#first")?
                                .get("https://zkp-ld.org/security#var")?
                                .get("@value")?;

                            let circuit_id = json
                                .get("https://zkp-ld.org/security#circuit")?
                                .get("@id")?;

                            Some(
                                pub_val == &public_val.value
                                    && pub_type == &public_val.r#type
                                    && pub_var == public_var
                                    && priv_var == private_var
                                    && circuit_id == id,
                            )
                        };

                        x().unwrap_or(false)
                    })
                    .unwrap();

                assert!(
                    graphs
                        .get("https://zkp-ld.org/security#private")
                        .and_then(|j| j.get("http://www.w3.org/1999/02/22-rdf-syntax-ns#first"))
                        .and_then(|j| j.get("https://zkp-ld.org/security#val"))
                        .and_then(|j| j.get("@id"))
                        .unwrap()
                        == blank_id
                );
            }
        }
    }

    subject
}
