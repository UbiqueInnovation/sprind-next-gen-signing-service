use std::time::SystemTime;

use chrono::{DateTime, Utc};
use rand::RngCore;
use rdf_proofs::KeyPairBase58Btc;
use serde_json::{json, Value as JsonValue};

pub(super) fn get_proof_cfg(issuer_key_id: &str) -> JsonValue {
    let now: DateTime<Utc> = SystemTime::now().into();
    let now = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    json!(
        {
            "@context": "https://www.w3.org/ns/data-integrity/v1",
            "type": "DataIntegrityProof",
            "created": now,
            "cryptosuite": "bbs-termwise-signature-2023",
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_key_id
        }
    )
}

pub fn generate_keypair<R: RngCore>(rng: &mut R) -> (String, String) {
    let kp = KeyPairBase58Btc::new(rng).unwrap();
    (kp.public_key, kp.secret_key)
}
