use std::collections::{BTreeMap, HashMap};

use anyhow::Context;
use rand_core::RngCore;
use rdf_proofs::{Circuit, KeyGraph, VcPair, VerifiableCredential};
use rdf_util::{
    oxrdf::{Graph, NamedNode, NamedOrBlankNode, Subject, Term},
    MultiGraph, Value as RdfValue,
};

use crate::device_binding::{DeviceBinding, DEVICE_BINDING_KEY};

use super::requirements::{DeviceBindingRequirement, ProofRequirement};

pub struct VerifiablePresentation {
    pub proof: MultiGraph,
    pub device_binding: Option<DeviceBinding>,
}

pub fn present<R: RngCore>(
    rng: &mut R,
    vc: VerifiableCredential,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingRequirement>,
    // proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<VerifiablePresentation> {
    let deanon_map = HashMap::<NamedOrBlankNode, Term>::new();
    let predicates = Vec::<Graph>::new();
    let circuits = HashMap::<NamedNode, Circuit>::new();

    // Figure out what information needs to be disclosed and prepare the vp
    let vc_document = rdf_util::Value::from(&vc.document);

    let (body, id) = vc_document["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .context("Couldn't get the vc_document credentialSubject!")?;

    let mut disclosed = BTreeMap::<String, RdfValue>::new();

    for requirement in requirements {
        match requirement {
            ProofRequirement::Required { key } => {
                disclosed.insert(key.clone(), body[key].clone());
            }
            ProofRequirement::Circuit { .. } => todo!(),
        }
    }

    let device_binding = if let Some(db_req) = device_binding {
        Some(DeviceBinding::new(
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
        )?)
    } else {
        None
    };

    let mut vp_document = vc_document.clone();

    // Remove the device binding object (don't disclose x,y)
    if device_binding.is_some() {
        vp_document
            .as_object_mut()
            .unwrap()
            .0
            .remove(DEVICE_BINDING_KEY);
    }

    vp_document["https://www.w3.org/2018/credentials#credentialSubject"] =
        RdfValue::Object(disclosed, id.clone());

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
        None,
        None,
        None,
    )?;

    Ok(VerifiablePresentation {
        proof: MultiGraph::new(&proof),
        device_binding,
    })

    /*
    let circuits = load_circuits(proving_keys);

    let mut subject = HashMap::<String, JsonValue>::new();
    let mut deanon_map = HashMap::<String, String>::new();
    let mut predicates = Vec::<String>::new();

    let issuer = format!(
        r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}"^^<https://w3id.org/security#multibase> .
        "#
    );

    let body = json["https://www.w3.org/2018/credentials#credentialSubject"]
        .as_object()
        .unwrap();

    let rdf_body = vc_document
        .get_value(
            NamedNode::new_unchecked("https://www.w3.org/2018/credentials#credentialSubject"),
            Some(&vc_document.get_graph_by_name(GraphName::DefaultGraph)),
        )
        .unwrap()
        .as_graph()
        .unwrap();

    let mut gen = generator::Blank::new_with_prefix("e".to_string());

    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::new();

    let canonical_doc = rdf_proofs::signature::transform(&vc.document).unwrap();
    */

    /*
    let db = if let Some(req) = device_binding {
        let x = Fr::from(BigUint::from_bytes_be(&req.x));
        let y = Fr::from(BigUint::from_bytes_be(&req.y));
        let bases_x = (0..2)
            .map(|_| G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
        let bases_y = (0..2)
            .map(|_| G1Projective::rand(rng).into_affine())
            .collect::<Vec<_>>();
        let scalars_x = vec![x, Fr::rand(rng)];
        let scalars_y = vec![y, Fr::rand(rng)];

        let commitment_x = G1Projective::msm_unchecked(&bases_x, &scalars_x).into_affine();
        let commitment_y = G1Projective::msm_unchecked(&bases_y, &scalars_y).into_affine();

        statements.add(PedersenCommitment::new_statement_from_params(
            bases_x.clone(),
            commitment_x,
        ));

        statements.add(PedersenCommitment::new_statement_from_params(
            bases_y.clone(),
            commitment_y,
        ));

        let x_index = canonical_doc
            .iter()
            .position(|t| {
                t == &Term::NamedNode(NamedNode::new_unchecked(
                    "https://example.org/deviceBinding/x",
                ))
            })
            .unwrap()
            + 2;
        let y_index = canonical_doc
            .iter()
            .position(|t| {
                t == &Term::NamedNode(NamedNode::new_unchecked(
                    "https://example.org/deviceBinding/y",
                ))
            })
            .unwrap()
            + 2;

        println!("indices: {x_index} {y_index}");
        println!("{:#?}", canonical_doc[x_index]);

        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, x_index), (1, 0)])));
        meta_statements
            .add_witness_equality(EqualWitnesses(BTreeSet::from([(0, y_index), (2, 0)])));

        witnesses.add(Witness::PedersenCommitment(scalars_x.clone()));
        witnesses.add(Witness::PedersenCommitment(scalars_y.clone()));

        let ped_params_x = PairingPedersenParams::<Bls12_381>::new_with_params(
            bases_x[0].into_group(),
            bases_x[1].into_group(),
        );
        let bbs_x = ped_params_x.commit_with_blinding(scalars_x[0], scalars_x[1]);
        let ped_params_y = PairingPedersenParams::<Bls12_381>::new_with_params(
            bases_y[0].into_group(),
            bases_y[1].into_group(),
        );
        let bbs_y = ped_params_y.commit_with_blinding(scalars_y[0], scalars_y[1]);

        use p256::ecdsa::signature::Signer;
        let signing_key = SigningKey::from_bytes(req.signing_key.as_slice().into()).unwrap();
        let signature: p256::ecdsa::Signature = signing_key.sign(req.binding_string.as_bytes());
        let signature: Vec<u8> = signature.to_vec();

        let verification = DeviceBindingVerification {
            binding_string: req.binding_string.clone(),
            x_index,
            y_index,
        };

        Some((
            create_device_binding(
                signature,
                req.public_key.clone(),
                req.binding_string.as_bytes().to_vec(),
                bbs_x,
                ped_params_x,
                bbs_y,
                ped_params_y,
            ),
            verification,
        ))
    } else {
        None
    };


    for req in reqs {
        match req {
            ProofRequirement::Required { key } => {
                let (key, value) = body.iter().find(|(k, _)| key == *k).unwrap();
                subject.insert(key.clone(), value.clone());
            }
            ProofRequirement::Circuit {
                id,
                private_var,
                private_key,
                public_var,
                public_val,
                ..
            } => {
                let (key, _) = body.iter().find(|(k, _)| private_key == *k).unwrap();
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

        /*
        if db.is_some() {
            disc_vc
                .as_object_mut()
                .unwrap()
                .remove("https://example.org/deviceBinding");
        }
        */

        disc_vc["https://www.w3.org/2018/credentials#credentialSubject"] = json!(subject);
        RdfQuery::from_jsonld(&disc_vc.to_string(), Some("e".to_string()))
            .await
            .unwrap()
            .to_rdf_string()
    };

    let vc_pair = VcPairString::new(
        &vc.document.to_string(),
        &vc.proof.to_string(),
        &disc_vc,
        &vc.proof.to_string(),
    );

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
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )
    .unwrap();

    proof
    */
}
