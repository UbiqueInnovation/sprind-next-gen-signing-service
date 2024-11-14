use std::{collections::HashMap, io::Cursor, time::SystemTime};

use ark_bls12_381::Bls12_381;
use chrono::{DateTime, Months, Utc};
use itertools::Itertools;
use legogroth16::circom::{r1cs::R1CSFile, CircomCircuit, R1CS as R1CSOrig};
use multibase::Base;
use next_gen_signatures::rdf::RdfQuery;
use oxrdf::{GraphName, NamedNode, Term};
use rand::{prelude::StdRng, SeedableRng};
use rdf_proofs::{
    ark_to_base64url, CircuitString, KeyPairBase58Btc, VcPairString, VerifiableCredential,
};
use rdf_types::generator;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

#[derive(Debug)]
pub struct Credential {
    graph: RdfQuery,
    rdf_doc: String,
    rdf_proof: String,
}

#[derive(Debug)]
pub struct Presentation {
    graph: RdfQuery,
}

impl Presentation {
    pub fn new(proof: &str) -> Self {
        let graph = RdfQuery::new(proof).unwrap();

        Self { graph }
    }
}

pub struct Circuits {
    verifying_keys: HashMap<String, String>,
    proving_keys: HashMap<String, String>,
}

impl Credential {
    pub fn new(doc: &str, proof: &str) -> Self {
        let (_, doc) = multibase::decode(doc).unwrap();
        let doc = String::from_utf8(doc).unwrap();

        let (_, proof) = multibase::decode(proof).unwrap();
        let proof = String::from_utf8(proof).unwrap();

        Self {
            graph: RdfQuery::new(&doc).unwrap(),
            rdf_doc: doc,
            rdf_proof: proof,
        }
    }

    pub fn as_json(&self) -> JsonValue {
        self.graph.to_json(
            Some(GraphName::DefaultGraph),
            Some(vec![
                Term::NamedNode(NamedNode::new_unchecked(
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                )),
                /*
                Term::NamedNode(NamedNode::new_unchecked(
                    "https://w3id.org/security#DataIntegrityProof",
                )),
                */
            ]),
            None,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValue {
    #[serde(rename = "@type")]
    pub r#type: String,
    #[serde(rename = "@value")]
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
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

impl ProofRequirement {
    pub fn get_key(&self) -> &str {
        match self {
            ProofRequirement::Required { key } => key,
            ProofRequirement::Circuit { private_key, .. } => private_key,
        }
    }
}

const ISSUER_ID: &str = "did:example:issuer0";
const ISSUER_KEY_ID: &str = "did:example:issuer0#bls12_381-g2-pub001";

const LESS_THAN_PUBLIC_ID: &str = "https://zkp-ld.org/circuit/ubique/lessThanPublic";
const LESS_THAN_PUBLIC_R1CS: &[u8] = include_bytes!("../circom/bls12381/less_than_public_64.r1cs");
const LESS_THAN_PUBLIC_WASM: &[u8] = include_bytes!("../circom/bls12381/less_than_public_64.wasm");

pub fn get_circuit_defs() -> HashMap<String, (&'static [u8], &'static [u8])> {
    HashMap::from([(
        LESS_THAN_PUBLIC_ID.to_string(),
        (LESS_THAN_PUBLIC_R1CS, LESS_THAN_PUBLIC_WASM),
    )])
}

pub fn get_sample_data() -> JsonValue {
    json!({
        "@type": "http://schema.org/Person",
        "@id": "did:example:johndoe",
        "http://schema.org/name": "John Doe",
        "http://schema.org/birthDate": {
            "@value": "1990-01-01T00:00:00Z",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "http://schema.org/telephone": "(425) 123-4567",
    })
}

pub fn generate_circuits(reqs: &Vec<ProofRequirement>) -> Circuits {
    type R1CS = R1CSOrig<Bls12_381>;

    let mut rng = StdRng::seed_from_u64(1337);
    let lookup = get_circuit_defs();

    let mut verifying_keys = HashMap::<String, String>::new();
    let mut proving_keys = HashMap::<String, String>::new();

    for req in reqs {
        match req {
            ProofRequirement::Circuit { id, .. } => {
                let (r1cs, _) = lookup.get(id).unwrap();
                let r1cs: R1CS = R1CSFile::new(Cursor::new(r1cs)).unwrap().into();

                let commit_witness_count = 1;
                let snark_proving_key = CircomCircuit::setup(r1cs)
                    .generate_proving_key(commit_witness_count, &mut rng)
                    .unwrap();

                // serialize to multibase
                let snark_proving_key_string = ark_to_base64url(&snark_proving_key).unwrap();
                let snark_verifying_key_string = ark_to_base64url(&snark_proving_key.vk).unwrap();

                verifying_keys.insert(id.clone(), snark_verifying_key_string);
                proving_keys.insert(id.clone(), snark_proving_key_string);
            }
            _ => (),
        }
    }

    Circuits {
        verifying_keys,
        proving_keys,
    }
}

pub fn load_circuits(keys: &HashMap<String, String>) -> HashMap<String, CircuitString> {
    type R1CS = R1CSOrig<Bls12_381>;

    let lookup = get_circuit_defs();
    let mut circuits = HashMap::<String, CircuitString>::new();

    for (id, key) in keys {
        let (r1cs, wasm) = lookup.get(id).unwrap();
        let r1cs: R1CS = R1CSFile::new(Cursor::new(r1cs)).unwrap().into();

        let wasm = multibase::encode(Base::Base64Url, wasm);
        let r1cs = ark_to_base64url(&r1cs).unwrap();

        let circuit = CircuitString {
            circuit_r1cs: r1cs,
            circuit_wasm: wasm,
            snark_proving_key: key.clone(),
        };

        circuits.insert(id.clone(), circuit);
    }

    circuits
}

pub fn get_proof_cfg() -> JsonValue {
    let now: DateTime<Utc> = SystemTime::now().into();
    let now = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    json!(
        {
            "@context": "https://www.w3.org/ns/data-integrity/v1",
            "type": "DataIntegrityProof",
            "created": now,
            "cryptosuite": "bbs-termwise-signature-2023",
            "proofPurpose": "assertionMethod",
            "verificationMethod": ISSUER_KEY_ID
        }
    )
}

pub fn get_issuer() -> (String, String) {
    let mut rng = StdRng::seed_from_u64(1337);

    let kp = KeyPairBase58Btc::new(&mut rng).unwrap();

    (kp.public_key, kp.secret_key)
}

pub async fn issue(data: JsonValue) -> Credential {
    let mut rng = StdRng::seed_from_u64(1337);
    let (issuer_pk, issuer_sk) = get_issuer();

    let issuer = RdfQuery::from_jsonld(
        &json!(
            {
                "@context": [
                    "https://www.w3.org/ns/controller/v1",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "id": ISSUER_ID,
                "type": "Controller",
                "verificationMethod": {
                    "id": ISSUER_KEY_ID,
                    "type": "Multikey",
                    "controller": ISSUER_ID,
                    "secretKeyMultibase": issuer_sk,
                    "publicKeyMultibase": issuer_pk
                }
            }
        )
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let now: DateTime<Utc> = SystemTime::now().into();
    let exp = now
        .checked_add_months(Months::new(36))
        .expect("Failed to get expiration date");
    let now = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let exp = exp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let credential_id = "http://example.org/credentials/person/0";

    let data = RdfQuery::from_jsonld(
        &json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/ns/data-integrity/v1"
            ],
            "id": credential_id,
            "type": "VerifiableCredential",
            "issuer": ISSUER_ID,
            "issuanceDate": now,
            "expirationDate": exp,
            "credentialSubject": data
        })
        .to_string(),
        Some("b".to_string()),
    )
    .await
    .unwrap();

    let proof_cfg = RdfQuery::from_jsonld(&get_proof_cfg().to_string(), Some("b".to_string()))
        .await
        .unwrap();

    let mut vc = VerifiableCredential::new(
        data.as_graph(GraphName::DefaultGraph),
        proof_cfg.as_graph(GraphName::DefaultGraph),
    );
    rdf_proofs::sign(
        &mut rng,
        &mut vc,
        &issuer.as_graph(GraphName::DefaultGraph).into(),
    )
    .expect("Failed to sign vc!");

    let doc = multibase::encode(multibase::Base::Base64Url, vc.document.to_string());
    let proof = multibase::encode(multibase::Base::Base64Url, vc.proof.to_string());

    Credential::new(&doc, &proof)
}

pub async fn present(
    vc: Credential,
    reqs: &Vec<ProofRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: String,
) -> Presentation {
    let mut rng = StdRng::seed_from_u64(1337);

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
                "id": ISSUER_ID,
                "type": "Controller",
                "verificationMethod": {
                    "id": ISSUER_KEY_ID,
                    "type": "Multikey",
                    "controller": ISSUER_ID,
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
        &mut rng,
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

pub async fn verify(
    pres: Presentation,
    issuer_pk: String,
    verifying_keys: HashMap<String, String>,
    reqs: &Vec<ProofRequirement>,
) -> JsonValue {
    let mut rng = StdRng::seed_from_u64(1337);
    let issuer = RdfQuery::from_jsonld(
        &json!(
            {
                "@context": [
                    "https://www.w3.org/ns/controller/v1",
                    "https://w3id.org/security/data-integrity/v2"
                ],
                "id": ISSUER_ID,
                "type": "Controller",
                "verificationMethod": {
                    "id": ISSUER_KEY_ID,
                    "type": "Multikey",
                    "controller": ISSUER_ID,
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
        &mut rng,
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

#[tokio::test]
pub async fn zkp() {
    let vc = issue(get_sample_data()).await;

    let reqs = vec![
        ProofRequirement::Required {
            key: "@id".to_string(),
        },
        ProofRequirement::Required {
            key: "@type".to_string(),
        },
        ProofRequirement::Required {
            key: "http://schema.org/name".to_string(),
        },
        ProofRequirement::Circuit {
            id: LESS_THAN_PUBLIC_ID.to_string(),
            private_var: "a".to_string(),
            private_key: "http://schema.org/birthDate".to_string(),

            public_var: "b".to_string(),
            public_val: PublicValue {
                r#type: "http://www.w3.org/2001/XMLSchema#dateTime".to_string(),
                value: "2000-01-01T00:00:00Z".to_string(),
            },
        },
        ProofRequirement::Circuit {
            id: LESS_THAN_PUBLIC_ID.to_string(),
            private_var: "a".to_string(),
            private_key: "http://schema.org/birthDate".to_string(),

            public_var: "b".to_string(),
            public_val: PublicValue {
                r#type: "http://www.w3.org/2001/XMLSchema#dateTime".to_string(),
                value: "2001-01-01T00:00:00Z".to_string(),
            },
        },
    ];

    let circuits = generate_circuits(&reqs);

    let (issuer_pk, _) = get_issuer();
    let pres = present(vc, &reqs, &circuits.proving_keys, issuer_pk.clone()).await;

    let json = verify(pres, issuer_pk, circuits.verifying_keys, &reqs).await;

    println!("Success!");

    println!("{json:#}");
}
