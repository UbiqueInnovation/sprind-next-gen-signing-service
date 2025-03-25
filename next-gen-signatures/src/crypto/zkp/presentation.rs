use std::collections::{BTreeSet, HashMap};

use ark_bls12_381::{Bls12_381, Config, Fr, G1Projective};
use ark_ec::{bls12::Bls12, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
use num_bigint::BigUint;
use oxrdf::{GraphName, NamedNode, Term};
use p256::ecdsa::SigningKey;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, EqualWitnesses, MetaStatements, Statements, Witness, Witnesses,
};
use proves::{
    device_binding as create_device_binding, dleq::PairingPedersenParams, p256_arithmetic, tom256,
    DeviceBinding,
};
use rand::RngCore;
use rdf_proofs::VcPairString;
use rdf_types::generator;
use serde_json::{json, Value as JsonValue};

use crate::rdf::RdfQuery;

use super::{
    load_circuits, Credential, DeviceBindingRequirement, DeviceBindingVerification, Presentation,
    ProofRequirement,
};

pub async fn present<R: RngCore>(
    rng: &mut R,
    vc: Credential,
    reqs: &Vec<ProofRequirement>,
    device_binding: Option<DeviceBindingRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: String,
    issuer_id: &str,
    issuer_key_id: &str,
) -> (
    Presentation,
    Option<(
        DeviceBinding<
            p256_arithmetic::ProjectivePoint,
            32,
            tom256::ProjectivePoint,
            40,
            Bls12<Config>,
        >,
        DeviceBindingVerification,
    )>,
) {
    let circuits = load_circuits(proving_keys);

    let json = vc.as_json();

    let mut subject = HashMap::<String, JsonValue>::new();
    let mut deanon_map = HashMap::<String, String>::new();
    let mut predicates = Vec::<String>::new();

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

    let mut statements = Statements::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::new();

    let canonical_doc = rdf_proofs::signature::transform(
        &RdfQuery::new(&vc.rdf_doc)
            .unwrap()
            .as_graph(GraphName::DefaultGraph),
    )
    .unwrap();

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

        if db.is_some() {
            disc_vc
                .as_object_mut()
                .unwrap()
                .remove("https://example.org/deviceBinding");
        }

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
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
    )
    .unwrap();

    (Presentation::new(&proof), db)
}
