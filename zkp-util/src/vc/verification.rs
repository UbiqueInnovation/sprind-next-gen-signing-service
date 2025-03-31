use anyhow::Context;
use ark_bls12_381::Bls12_381;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, r1cs_legogroth16::VerifyingKey, EqualWitnesses, MetaStatements,
    Statements,
};
use rand_core::RngCore;
use rdf_proofs::KeyGraph;
use rdf_util::{
    oxrdf::{BlankNode, GraphName, Literal, NamedNode, Subject, Term, Triple},
    ObjectId, Value as RdfValue,
};
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, HashMap};

use crate::{
    device_binding::{DEVICE_BINDING_KEY, DEVICE_BINDING_KEY_X, DEVICE_BINDING_KEY_Y},
    vc::index::index_of_vp,
};

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
    let verifying_keys = HashMap::<NamedNode, VerifyingKey<Bls12_381>>::new();

    let credential = presentation.proof.to_value(GraphName::DefaultGraph)
        ["https://www.w3.org/2018/credentials#verifiableCredential"]
        .clone();

    // Verify the device binding
    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();

    if let Some(db) = presentation.device_binding {
        let Some(params) = device_binding else {
            anyhow::bail!("Device binding verification params expected!")
        };

        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_x,
        ));
        // add the statements about the public key commitment
        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_y,
        ));

        // let terms = rdf_proofs::signature::transform(&credential.to_graph(None))?;
        // let x_key_term = Term::NamedNode(NamedNode::new_unchecked(DEVICE_BINDING_KEY_X));
        // let x_index = terms.iter().position(|t| t == &x_key_term).unwrap() + 2;
        // let y_key_term = Term::NamedNode(NamedNode::new_unchecked(DEVICE_BINDING_KEY_Y));
        // let y_index = terms.iter().position(|t| t == &y_key_term).unwrap() + 2;

        // let (db_map, db_id) = credential[DEVICE_BINDING_KEY]
        //     .as_object()
        //     .context("verifiable credential has no device_binding")?;

        // anyhow::ensure!(
        //     !matches!(db_id, ObjectId::None),
        //     "device binding object id can't be none!"
        // );
        // let x_value = db_map
        //     .get(DEVICE_BINDING_KEY_X)
        //     .context("device binding has no x value")?;
        // let y_value = db_map
        //     .get(DEVICE_BINDING_KEY_Y)
        //     .context("device binding has no x value")?;

        // let x_triple = Triple::new(
        //     match db_id {
        //         ObjectId::BlankNode(b) => Subject::BlankNode(BlankNode::new_unchecked(b)),
        //         ObjectId::NamedNode(n) => Subject::NamedNode(NamedNode::new_unchecked(n)),
        //         ObjectId::None => unreachable!(),
        //     },
        //     NamedNode::new_unchecked(DEVICE_BINDING_KEY_X),
        //     Term::Literal(match x_value {
        //         RdfValue::Typed(v, t) => Literal::new_typed_literal(v, NamedNode::new_unchecked(t)),
        //         _ => anyhow::bail!("Invalid device_binding x value: {x_value:#?}"),
        //     }),
        // );
        // let y_triple = Triple::new(
        //     match db_id {
        //         ObjectId::BlankNode(b) => Subject::BlankNode(BlankNode::new_unchecked(b)),
        //         ObjectId::NamedNode(n) => Subject::NamedNode(NamedNode::new_unchecked(n)),
        //         ObjectId::None => unreachable!(),
        //     },
        //     NamedNode::new_unchecked(DEVICE_BINDING_KEY_Y),
        //     Term::Literal(match y_value {
        //         RdfValue::Typed(v, t) => Literal::new_typed_literal(v, NamedNode::new_unchecked(t)),
        //         _ => anyhow::bail!("Invalid device_binding y value: {y_value:#?}"),
        //     }),
        // );
        // anyhow::ensure!(
        //     canonical_triples.contains(&x_triple),
        //     "canonical triples doesn't contain x triple"
        // );
        // anyhow::ensure!(
        //     canonical_triples.contains(&y_triple),
        //     "canonical triples doesn't contain y triple"
        // );

        // let x_index = canonical_triples
        //     .iter()
        //     .position(|t| t == &x_triple)
        //     .unwrap()
        //     * 3 // every triple contains 3 messages
        //     + 2 // index 2 is the object (value)
        //     + 1; // there is a boundary (see rdf-proofs/src/signature.rs:107)
        // let y_index = canonical_triples
        //     .iter()
        //     .position(|t| t == &y_triple)
        //     .unwrap()
        //     * 3 // every triple contains 3 messages
        //     + 2 // index 2 is the object (value)
        //     + 1; // there is a boundary (see rdf-proofs/src/signature.rs:107)

        // TODO: Find out x and y index of the document in canonical form
        // println!("xy2: {x_index} {y_index}");

        let x_index = index_of_vp(
            &presentation.proof.dataset(),
            &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X),
        ) + 1;
        let y_index = index_of_vp(
            &presentation.proof.dataset(),
            &NamedNode::new_unchecked(DEVICE_BINDING_KEY_Y),
        ) + 1;
        println!("xy2: {x_index} {y_index}");

        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (1, 0)])));
        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (2, 0)])));

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

    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    let success = rdf_proofs::verify_proof(
        rng,
        &presentation.proof.dataset(),
        &issuer,
        None,
        None,
        verifying_keys,
        Some(statements),
        Some(meta_statements),
    );

    assert!(success.is_ok(), "{success:#?}");

    let body = credential["https://www.w3.org/2018/credentials#credentialSubject"].to_json();

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
