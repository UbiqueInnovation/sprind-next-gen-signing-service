use std::collections::HashMap;

use multibase::Base;
use oxrdf::{GraphName, NamedNode, Term};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

use crate::rdf::RdfQuery;

#[derive(Debug)]
pub struct Credential {
    pub(super) graph: RdfQuery,
    pub(super) rdf_doc: String,
    pub(super) rdf_proof: String,
}

#[derive(Debug)]
pub struct Presentation {
    pub(super) graph: RdfQuery,
}

impl Presentation {
    pub fn new(proof: &str) -> Self {
        let graph = RdfQuery::new(proof).unwrap();

        Self { graph }
    }

    pub fn serialize(&self) -> String {
        let str = self.graph.to_rdf_string();
        multibase::encode(Base::Base64Url, str)
    }

    pub fn deserialize(str: &str) -> Self {
        let (_, quads) = multibase::decode(str).unwrap();
        let quads = String::from_utf8(quads).unwrap();
        Self::new(&quads)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Circuits {
    pub verifying_keys: HashMap<String, String>,
    pub proving_keys: HashMap<String, String>,
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

    pub fn serialize(&self) -> JsonValue {
        let json = self.as_json();
        let encoded = multibase::encode(
            Base::Base64Url,
            json!({
                "rdf_doc": self.rdf_doc,
                "rdf_proof": self.rdf_proof
            })
            .to_string(),
        );

        json!({
            "humanReadable": json,
            "encoded": encoded,
        })
    }

    pub fn deserialize_encoded(encoded: &str) -> Self {
        let (_, decoded) = multibase::decode(encoded).unwrap();

        let decoded = String::from_utf8(decoded).unwrap();

        println!("{decoded}");

        let json = serde_json::from_str::<JsonValue>(&decoded).unwrap();

        println!("{json}");

        let rdf_doc = json["rdf_doc"].as_str().unwrap();
        let rdf_doc = multibase::encode(Base::Base64, rdf_doc);

        let rdf_proof = json["rdf_proof"].as_str().unwrap();
        let rdf_proof = multibase::encode(Base::Base64, rdf_proof);

        Self::new(&rdf_doc, &rdf_proof)
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
