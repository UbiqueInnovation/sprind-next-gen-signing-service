use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Context;
use ark_bls12_381::Bls12_381;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, EqualWitnesses, MetaStatements, Statements, Witness, Witnesses,
};
use rand_core::RngCore;
use rdf_proofs::{KeyGraph, VcPair, VerifiableCredential};
use rdf_util::{
    oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Subject, Term},
    BlankGenerator, MultiGraph, ObjectId, Value as RdfValue,
};

use crate::{
    circuits::load_circuits,
    device_binding::{
        DeviceBinding, DeviceBindingPresentation, DEVICE_BINDING_KEY, DEVICE_BINDING_KEY_X,
        DEVICE_BINDING_KEY_Y,
    },
    vc::index::index_of_vc,
};

use super::requirements::{DeviceBindingRequirement, ProofRequirement};

pub struct VerifiablePresentation {
    pub proof: MultiGraph,
    pub device_binding: Option<DeviceBindingPresentation>,
}

#[allow(clippy::too_many_arguments)]
pub fn present<R: RngCore>(
    rng: &mut R,
    vc: VerifiableCredential,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<VerifiablePresentation> {
    let mut deanon_map = HashMap::<NamedOrBlankNode, Term>::new();
    let mut predicates = Vec::<Graph>::new();
    let circuits = load_circuits(proving_keys);

    // Figure out what information needs to be disclosed and prepare the vp
    let vc_document = rdf_util::Value::from(&vc.document);

    let (body, id) = vc_document["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let mut generator = BlankGenerator::default();
    let mut disclosed = BTreeMap::<String, RdfValue>::new();

    for requirement in requirements {
        match requirement {
            ProofRequirement::Required { key } => {
                disclosed.insert(key.clone(), body[key].clone());
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
                ..
            } => {
                let (_, value) = body.iter().find(|(k, _)| private_key == *k).unwrap();

                let value = match value {
                    RdfValue::String(s) => Term::Literal(Literal::new_simple_literal(s)),
                    RdfValue::Typed(v, t) => {
                        Term::Literal(Literal::new_typed_literal(v, NamedNode::new_unchecked(t)))
                    }
                    _ => anyhow::bail!("Invalid private value"),
                };

                let blank_id = generator.next("e");
                let blank = deanon_map
                    .iter()
                    .find_map(|(k, v)| (v == &value).then_some(k.clone()))
                    .unwrap_or_else(|| {
                        NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(blank_id.clone()))
                    });

                deanon_map.insert(blank.clone(), value);

                let public_val = match public_val {
                    RdfValue::String(s) => format!("\"{s}\""),
                    RdfValue::Typed(v, t) => format!("\"{v}\"^^<{t}>"),
                    _ => unimplemented!(),
                };

                let predicate = rdf_util::from_str(format!(
                    r#"
                    _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
                    _:b0 <https://zkp-ld.org/security#circuit> <{id}> .
                    _:b0 <https://zkp-ld.org/security#private> _:b1 .
                    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
                    _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
                    _:b2 <https://zkp-ld.org/security#var> "{private_var}" .
                    _:b2 <https://zkp-ld.org/security#val> _:{blank_id} .
                    _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
                    _:b0 <https://zkp-ld.org/security#public> _:b3 .
                    _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
                    _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
                    _:b4 <https://zkp-ld.org/security#var> "{public_var}" .
                    _:b4 <https://zkp-ld.org/security#val> {public_val} .
                    _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
                    "#
                )).unwrap().to_graph(None);

                predicates.push(predicate);

                disclosed.insert(
                    private_key.clone(),
                    RdfValue::ObjectRef(ObjectId::BlankNode(blank_id)),
                );
            }
        }
    }

    let mut vp_document = vc_document.clone();

    vp_document["https://www.w3.org/2018/credentials#credentialSubject"] =
        RdfValue::Object(disclosed, id.clone());

    // Handle device binding
    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::<Bls12_381>::new();

    let device_binding = if let Some(db_req) = device_binding {
        let db = DeviceBinding::new(
            rng,
            db_req.public_key,
            db_req.message,
            db_req.message_signature,
            &db_req.comm_key_secp_label,
            &db_req.comm_key_tom_label,
            &db_req.comm_key_bls_label,
            &db_req.bpp_setup_label,
            db_req.merlin_transcript_label,
            db_req.challenge_label,
        )?;

        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_x,
        ));

        statements.add(PedersenCommitment::new_statement_from_params(
            db.bls_comm_key.clone(),
            db.bls_comm_pk_y,
        ));

        witnesses.add(Witness::PedersenCommitment(db.bls_scalars_x.clone()));
        witnesses.add(Witness::PedersenCommitment(db.bls_scalars_y.clone()));

        let (db_map, db_id) = vc_document[DEVICE_BINDING_KEY]
            .as_object()
            .context("verifiable credential has no device_binding")?;

        anyhow::ensure!(
            !matches!(db_id, ObjectId::None),
            "device binding object id can't be none!"
        );
        let RdfValue::Typed(x_value, x_type) = db_map
            .get(DEVICE_BINDING_KEY_X)
            .context("device binding has no x value")?
        else {
            anyhow::bail!("device binding invalid x value")
        };
        let x_term = Term::Literal(Literal::new_typed_literal(
            x_value,
            NamedNode::new_unchecked(x_type),
        ));

        let RdfValue::Typed(y_value, y_type) = db_map
            .get(DEVICE_BINDING_KEY_Y)
            .context("device binding has no y value")?
        else {
            anyhow::bail!("device binding invalid y value")
        };
        let y_term = Term::Literal(Literal::new_typed_literal(
            y_value,
            NamedNode::new_unchecked(y_type),
        ));

        let x_index = index_of_vc(&vc, &x_term);
        let y_index = index_of_vc(&vc, &y_term);

        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (1, 0)])));
        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (2, 0)])));

        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_X] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d0".into()));
        vp_document[DEVICE_BINDING_KEY][DEVICE_BINDING_KEY_Y] =
            RdfValue::ObjectRef(ObjectId::BlankNode("d1".into()));
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d0")),
            x_term.clone(),
        );
        deanon_map.insert(
            NamedOrBlankNode::BlankNode(BlankNode::new_unchecked("d1")),
            y_term.clone(),
        );

        Some(db)
    } else {
        None
    };

    // Create the proof
    let issuer = KeyGraph::from(rdf_util::from_str_with_hint(format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    ), Subject::NamedNode(NamedNode::new_unchecked(issuer_id)))?.to_graph(None));

    let vc_pairs = vec![VcPair::new(
        vc.clone(),
        VerifiableCredential {
            document: vp_document.to_graph(None),
            proof: vc.proof.clone(),
        },
    )];

    let proof = rdf_proofs::derive_proof(
        rng,
        &vc_pairs,
        &deanon_map,
        &issuer,
        None,
        None,
        None,
        None,
        None,
        predicates,
        circuits,
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )?;

    Ok(VerifiablePresentation {
        proof: MultiGraph::new(&proof),
        device_binding: device_binding.map(|db| db.present()),
    })
}
