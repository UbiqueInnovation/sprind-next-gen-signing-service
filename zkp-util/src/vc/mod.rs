use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::SystemTime,
};

use anyhow::Context;
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_std::UniformRand;
use chrono::{DateTime, Months, Utc};
use num_bigint::BigUint;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, r1cs_legogroth16::VerifyingKey, EqualWitnesses, MetaStatements,
    Statements, Witness, Witnesses,
};
use rand_core::{OsRng, RngCore};
use rdf_proofs::{Circuit, KeyGraph, VcPair, VcPairString, VerifiableCredential};
use rdf_util::{
    oxrdf::{Dataset, Graph, GraphName, NamedNode, NamedOrBlankNode, Subject, Term},
    MultiGraph, ObjectId, Value as RdfValue,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value as JsonValue;

use crate::circuits::load_circuits;

pub fn issue<R: RngCore>(
    rng: &mut R,
    claims: RdfValue,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    exp_months: u32,
    device_binding: Option<(String, String)>,
) -> anyhow::Result<VerifiableCredential> {
    let issuer = rdf_util::from_str_with_hint(
        format!(
            r#"
            <{issuer_id}> <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
            <{issuer_key_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
            <{issuer_key_id}> <https://w3id.org/security#controller> <{issuer_id}> .
            <{issuer_key_id}> <https://w3id.org/security#secretKeyMultibase> "{issuer_sk}" .
            <{issuer_key_id}> <https://w3id.org/security#publicKeyMultibase> "{issuer_pk}" .
            "#
        ),
        Subject::NamedNode(NamedNode::new_unchecked(issuer_id)),
    )?;

    // TODO: Do not before, not after
    let now: DateTime<Utc> = SystemTime::now().into();
    let exp = now
        .checked_add_months(Months::new(exp_months))
        .expect("Failed to get expiration date");
    let now = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let exp = exp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let credential_id = "http://example.org/credentials/person/0";

    let (claims, claims_id) = claims.as_object().context("Claims is not an object!")?;
    let (claims, mut claims_id) = (claims.clone(), claims_id.clone());
    if let ObjectId::BlankNode(_) = claims_id {
        claims_id = ObjectId::None;
    };

    let mut data = rdf_util::from_str(&format!(
        r#"
        <{credential_id}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
        <{credential_id}> <https://www.w3.org/2018/credentials#issuer> <{issuer_id}> .
        <{credential_id}> <https://www.w3.org/2018/credentials#issuanceDate> "{now}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        <{credential_id}> <https://www.w3.org/2018/credentials#expirationDate> "{exp}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        "#,
    ))?;
    data["https://www.w3.org/2018/credentials#credentialSubject"] =
        RdfValue::Object(claims, claims_id);

    if let Some((x, y)) = device_binding {
        // TODO: replace example.org/deviceBinding
        data["https://example.org/deviceBinding"] = RdfValue::Object(
            BTreeMap::from([
                (
                    "https://example.org/deviceBinding#x".into(),
                    // TODO: replace http://www.w3.org/2001/XMLSchema#base64Binary with custom type
                    RdfValue::Typed(x, "http://www.w3.org/2001/XMLSchema#base64Binary".into()),
                ),
                (
                    "https://example.org/deviceBinding#y".into(),
                    // TODO: replace http://www.w3.org/2001/XMLSchema#base64Binary with custom type
                    RdfValue::Typed(y, "http://www.w3.org/2001/XMLSchema#base64Binary".into()),
                ),
            ]),
            ObjectId::None,
        )
    }

    let proof_cfg = rdf_util::from_str(&format!(
        r#"
        _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
        _:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
        _:b0 <http://purl.org/dc/terms/created> "{now}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
        _:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
        _:b0 <https://w3id.org/security#verificationMethod> <{issuer_key_id}> .
        "#
    ))?;

    let mut vc = VerifiableCredential::new(data.to_graph(None), proof_cfg.to_graph(None));
    rdf_proofs::sign(rng, &mut vc, &issuer.to_graph(None).into()).expect("Failed to sign vc!");

    Ok(vc)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValue {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofRequirement {
    Required {
        key: String,
    },
    Circuit {
        id: String,

        private_var: String,
        private_key: String,

        public_var: String,
        public_val: PublicValue,
    },
}

#[derive(Debug, Clone)]
pub struct DeviceBindingRequirement {
    pub public_key: Vec<u8>,
    pub signing_key: Vec<u8>,

    pub binding_string: String,

    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub fn present<R: RngCore>(
    rng: &mut R,
    vc: VerifiableCredential,
    requirements: &Vec<ProofRequirement>,
    // device_binding: Option<DeviceBindingRequirement>,
    // proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<MultiGraph> {
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

    let mut vp_document = vc_document.clone();
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

    Ok(MultiGraph::new(&proof))

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

pub fn verify<R: RngCore>(
    rng: &mut R,
    presentation: MultiGraph,
    // pres: Presentation,
    // verifying_keys: HashMap<String, String>,
    requirements: &Vec<ProofRequirement>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    // db: Option<(
    //     DeviceBinding<
    //         p256_arithmetic::ProjectivePoint,
    //         32,
    //         tom256::ProjectivePoint,
    //         40,
    //         Bls12<Config>,
    //     >,
    //     DeviceBindingVerification,
    // )>,
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

    let success = rdf_proofs::verify_proof(
        rng,
        &presentation.dataset(),
        &issuer,
        None,
        None,
        verifying_keys,
        None,
        None,
    );

    assert!(success.is_ok(), "{success:#?}");

    let body = presentation.to_value(GraphName::DefaultGraph)
        ["https://www.w3.org/2018/credentials#verifiableCredential"]
        ["https://www.w3.org/2018/credentials#credentialSubject"]
        .to_json();

    for requirement in requirements {
        match requirement {
            ProofRequirement::Required { key } => anyhow::ensure!(body.get(key).is_some()),
            ProofRequirement::Circuit { .. } => todo!(),
        }
    }

    Ok(body)

    // Ok(presentation["https://www.w3.org/2018/credentials#credentialSubject"].to_json())

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

#[test]
pub fn test_roundtrip() {
    let mut rng = OsRng;

    const ISSUER_ID: &str = "did:example:issuer0";
    const ISSUER_KEY_ID: &str = "did:example:issuer0#key01";
    const ISSUER_SK: &str = "z489BikWV616m6F5ayUNDnLxWpHVmw3tG6hSgCVE9ZxDEXz3";
    const ISSUER_PK: &str = "zUC77roR12AzeB1bjwU6eK86NBBpJf5Rxvyqh8QcaEK6BxRTDoQucp2DSARoAABMWchDk4zxXmwfpHUeaWBg7T4q3Pne9YfnZBhStoGBmCzQcdj8pY3joRbr37w4TMcU1Pipqdp";

    let claims = RdfValue::Object(
        BTreeMap::from([
            (
                "https://schema.org/name".into(),
                RdfValue::String("John Doe".into()),
            ),
            (
                "https://schema.org/telephone".into(),
                RdfValue::String("+1 634 535 1587".into()),
            ),
        ]),
        ObjectId::None,
    );

    let vc = issue(
        &mut rng,
        claims,
        ISSUER_PK,
        ISSUER_SK,
        ISSUER_ID,
        ISSUER_KEY_ID,
        12,
        None,
    )
    .unwrap();

    println!("{}", vc.to_string());

    let requirements = vec![ProofRequirement::Required {
        key: "https://schema.org/name".into(),
    }];

    let vp = present(
        &mut rng,
        vc,
        &requirements,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    let body = verify(
        &mut rng,
        vp,
        &requirements,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    println!("{body:#}")
}
