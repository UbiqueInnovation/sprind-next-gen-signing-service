use ark_bls12_381::Bls12_381;
use proof_system::prelude::r1cs_legogroth16::VerifyingKey;
use rand_core::RngCore;
use rdf_proofs::KeyGraph;
use rdf_util::oxrdf::{GraphName, NamedNode, Subject};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

use super::{
    presentation::VerifiablePresentation,
    requirements::{DeviceBindingVerificationParams, ProofRequirement},
};

pub fn verify<R: RngCore>(
    rng: &mut R,
    presentation: VerifiablePresentation,
    // pres: Presentation,
    // verifying_keys: HashMap<String, String>,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingVerificationParams>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<JsonValue> {
    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    let verifying_keys = HashMap::<NamedNode, VerifyingKey<Bls12_381>>::new();

    // Verify the device binding
    if let Some(db) = presentation.device_binding {
        let Some(params) = device_binding else {
            anyhow::bail!("Device binding verification params expected!")
        };

        db.verify(
            rng,
            params.message,
            &params.comm_key_secp_label,
            &params.comm_key_tom_label,
            &params.comm_key_bls_label,
            &params.bpp_setup_label,
            params.merlin_transcript_label,
            params.challenge_label,
        )?;
    }

    let success = rdf_proofs::verify_proof(
        rng,
        &presentation.proof.dataset(),
        &issuer,
        None,
        None,
        verifying_keys,
        None,
        None,
    );

    assert!(success.is_ok(), "{success:#?}");

    let body = presentation.proof.to_value(GraphName::DefaultGraph)
        ["https://www.w3.org/2018/credentials#verifiableCredential"]
        ["https://www.w3.org/2018/credentials#credentialSubject"]
        .to_json();

    // Make sure the claims were reveiled
    for requirement in requirements {
        match requirement {
            ProofRequirement::Required { key } => anyhow::ensure!(body.get(key).is_some()),
            ProofRequirement::Circuit { .. } => todo!(),
        }
    }

    Ok(body)

    /*
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

    let mut meta_statements = MetaStatements::new();
    let statements = if let Some((db, verification)) = db {
        assert!(
            db.verify(verification.binding_string.as_bytes().to_vec()),
            "zk attest failed"
        );

        let bases_x = vec![
            db.eq_x.g2_params.g.into_affine(),
            db.eq_x.g2_params.h.into_affine(),
        ];
        let bases_y = vec![
            db.eq_y.g2_params.g.into_affine(),
            db.eq_y.g2_params.h.into_affine(),
        ];
        let cx = db.eq_x.c2.into_affine();
        let cy = db.eq_y.c2.into_affine();

        let mut statements = Statements::<Bls12_381>::new();

        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(bases_x, cx));
        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(bases_y, cy));

        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (0, verification.x_index),
            (1, 0),
        ])));
        meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([
            (0, verification.y_index),
            (2, 0),
        ])));

        Some(statements)
    } else {
        None
    };

    let success = rdf_proofs::verify_proof_string(
        rng,
        &pres.graph.to_rdf_string(),
        &issuer,
        None,
        None,
        Some(verifying_keys),
        statements,
        Some(meta_statements),
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

     */
}
