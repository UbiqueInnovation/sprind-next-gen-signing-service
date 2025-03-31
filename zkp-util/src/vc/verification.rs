use anyhow::Context;
use ark_bls12_381::Bls12_381;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, r1cs_legogroth16::VerifyingKey, EqualWitnesses, MetaStatements,
    Statements,
};
use rand_core::RngCore;
use rdf_proofs::{multibase_to_ark, KeyGraph};
use rdf_util::{
    oxrdf::{GraphName, NamedNode, Subject},
    Value as RdfValue,
};
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, HashMap};

use crate::{
    device_binding::{DEVICE_BINDING_KEY_X, DEVICE_BINDING_KEY_Y},
    vc::index::index_of_vp,
};

use super::{
    presentation::VerifiablePresentation,
    requirements::{DeviceBindingVerificationParams, ProofRequirement},
};

pub fn verify<R: RngCore>(
    rng: &mut R,
    presentation: VerifiablePresentation,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingVerificationParams>,
    verifying_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<JsonValue> {
    let verifying_keys: HashMap<NamedNode, VerifyingKey<Bls12_381>> = verifying_keys
        .iter()
        .map(|(k, v)| (NamedNode::new_unchecked(k), multibase_to_ark(v).unwrap()))
        .collect();

    let proof = presentation.proof.to_value(GraphName::DefaultGraph);
    let credential = proof["https://www.w3.org/2018/credentials#verifiableCredential"].clone();
    let predicates = match proof.get("https://zkp-ld.org/security#predicate") {
        Some(RdfValue::Object(m, id)) => vec![RdfValue::Object(m.clone(), id.clone())],
        Some(RdfValue::Array(array)) => array.clone(),
        None => vec![],
        _ => anyhow::bail!("Invalid predicates: {proof:#?}"),
    };

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

        let x_index = index_of_vp(
            &presentation.proof.dataset(),
            &NamedNode::new_unchecked(DEVICE_BINDING_KEY_X),
        ) + 1;
        let y_index = index_of_vp(
            &presentation.proof.dataset(),
            &NamedNode::new_unchecked(DEVICE_BINDING_KEY_Y),
        ) + 1;

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

    let result = rdf_proofs::verify_proof(
        rng,
        &presentation.proof.dataset(),
        &issuer,
        None,
        None,
        verifying_keys,
        Some(statements),
        Some(meta_statements),
    );

    assert!(result.is_ok(), "{result:#?}");

    let body = credential["https://www.w3.org/2018/credentials#credentialSubject"].to_json();

    // Make sure the claims were reveiled
    for requirement in requirements {
        match requirement {
            ProofRequirement::Required { key } => anyhow::ensure!(body.get(key).is_some()),
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
            } => {
                let private_val = &credential
                    ["https://www.w3.org/2018/credentials#credentialSubject"][private_key];

                let object_id = match private_val {
                    RdfValue::Object(_, id) | RdfValue::ObjectRef(id) => id,
                    _ => anyhow::bail!(
                        "Invalid private value, expected object, got {private_val:#?}"
                    ),
                };

                // Find the matching predicate
                let predicate = predicates
                    .iter()
                    .find(|p| {
                        p["https://zkp-ld.org/security#circuit"].id().unwrap() == id
                            && &p["https://zkp-ld.org/security#public"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#val"]
                                == public_val
                            && p["https://zkp-ld.org/security#public"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#var"]
                                .as_string()
                                .unwrap()
                                == public_var
                            && p["https://zkp-ld.org/security#private"]
                                ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                                ["https://zkp-ld.org/security#var"]
                                .as_string()
                                .unwrap()
                                == private_var
                    })
                    .context("Couldn't find predicate!")?;

                // Make sure the id of the blank node matches the id specified in the predicate
                let Some(private_id) = predicate["https://zkp-ld.org/security#private"]
                    ["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"]
                    ["https://zkp-ld.org/security#val"]
                    .id()
                else {
                    anyhow::bail!("Couldn't get the private value of the circuit: {predicates:#?}")
                };
                anyhow::ensure!(object_id == private_id, "circuit not satisfied!")
            }
        }
    }

    Ok(body)
}
