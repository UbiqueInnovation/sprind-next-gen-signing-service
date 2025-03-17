use next_gen_signatures::crypto::zkp::{
    self, circuits::LESS_THAN_PUBLIC_ID, ProofRequirement, PublicValue,
};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use rdf_proofs::KeyPairBase58Btc;

use serde_json::{json, Value as JsonValue};

const ISSUER_ID: &str = "did:example:issuer0";
const ISSUER_KEY_ID: &str = "did:example:issuer0#bls12_381-g2-pub001";

const VC_VALIDITY_MONTHS: u32 = 36;

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

pub fn get_issuer<R: RngCore>(rng: &mut R) -> (String, String) {
    let kp = KeyPairBase58Btc::new(rng).unwrap();
    (kp.public_key, kp.secret_key)
}

#[tokio::test]
pub async fn jsonld_zkp_flow() {
    let mut rng = StdRng::seed_from_u64(1337);

    let (issuer_pk, issuer_sk) = get_issuer(&mut rng);

    let vc = zkp::issue(
        &mut rng,
        get_sample_data(),
        issuer_pk.clone(),
        issuer_sk,
        ISSUER_ID,
        ISSUER_KEY_ID,
        VC_VALIDITY_MONTHS,
    )
    .await;

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

    let circuits = zkp::circuits::generate_circuits(&mut rng, &reqs);

    let (pres, _) = zkp::present(
        &mut rng,
        vc,
        &reqs,
        &circuits.proving_keys,
        issuer_pk.clone(),
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .await;

    let json = zkp::verify(
        &mut rng,
        pres,
        issuer_pk,
        circuits.verifying_keys,
        &reqs,
        ISSUER_ID,
        ISSUER_KEY_ID,
        None,
    )
    .await;

    println!("Success!");

    println!("{json:#}");
}
