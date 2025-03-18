use ark_bls12_381::{Bls12_381, Fr};
use base64::{prelude::BASE64_STANDARD, Engine};
use bbs_plus::prelude::{SignatureG1, SignatureParamsG1};
use next_gen_signatures::crypto::zkp::{
    circuits::LESS_THAN_PUBLIC_ID, ProofRequirement, PublicValue,
};
use p256::ecdsa::SigningKey;
use proof_system::prelude::{
    bbs_plus::PoKBBSSignatureG1Prover, bound_check_legogroth16::BoundCheckLegoGroth16Prover,
};
use proves::p256_arithmetic;
use rand::{prelude::StdRng, RngCore, SeedableRng};

use proves::group::Group;

use next_gen_signatures::crypto::zkp;
use rdf_proofs::KeyPairBase58Btc;
use serde_json::json;

pub type ScalarField = Fr;
pub type Signature = SignatureG1<Bls12_381>;
pub type SignatureParams = SignatureParamsG1<Bls12_381>;
pub type StatementProver = PoKBBSSignatureG1Prover<Bls12_381>;
pub type BoundsStatementProver = BoundCheckLegoGroth16Prover<Bls12_381>;

const ISSUER_ID: &str = "did:example:issuer0";
const ISSUER_KEY_ID: &str = "did:example:issuer0#bls12_381-g2-pub001";

const VC_VALIDITY_MONTHS: u32 = 36;

pub fn get_issuer<R: RngCore>(rng: &mut R) -> (String, String) {
    let kp = KeyPairBase58Btc::new(rng).unwrap();
    (kp.public_key, kp.secret_key)
}

#[tokio::test]
pub async fn device_binding_test() -> anyhow::Result<()> {
    let mut rng = StdRng::seed_from_u64(1337);
    // USE-CASE: We have a p256 private key that we use to bind the bbs signature to. For
    // that we use ZK-Attest by cloudflare and equality of DL accross different groups (paper by microsoft).
    // We then use the Bls12381 commitment as a witness and add an equality statement that this is indeed
    // part of our signed signature.
    use proves::group::Coords;
    let signing_key = SigningKey::random(&mut rng);
    let pub_key = signing_key.verifying_key().to_sec1_bytes().to_vec();
    let pub_key_p = p256_arithmetic::ProjectivePoint::from_bytes(&pub_key).unwrap();
    let pub_key_p = pub_key_p.to_affine();
    let x_bytes = pub_key_p.x().to_be_bytes();
    let y_bytes = pub_key_p.y().to_be_bytes();

    println!("bytes: {x_bytes:?} {y_bytes:?}");

    let binding_string = r#"{ "timestamp" : now(), "nonce" : "1234", "whatever"}"#.to_string();
    let device_xy = (
        BASE64_STANDARD.encode(&x_bytes),
        BASE64_STANDARD.encode(y_bytes),
    );

    let (issuer_pk, issuer_sk) = get_issuer(&mut rng);

    let vc = zkp::issue_with_device_binding(
        &mut rng,
        json!({
            "@type": "http://schema.org/Person",
            "@id": "did:example:johndoe",
            "http://schema.org/name": "John Doe",
            "http://schema.org/birthDate": {
                "@value": "1990-01-01T00:00:00Z",
                "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "http://schema.org/telephone": "(425) 123-4567",
        }),
        issuer_pk.clone(),
        issuer_sk,
        ISSUER_ID,
        ISSUER_KEY_ID,
        VC_VALIDITY_MONTHS,
        device_xy,
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
        ProofRequirement::DeviceBinding {
            public_key: pub_key,
            signing_key: signing_key.to_bytes().to_vec(),
            binding_string: binding_string.clone(),
            x: x_bytes.to_vec(),
            y: y_bytes.to_vec(),
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
    ];

    let circuits = zkp::circuits::generate_circuits(&mut rng, &reqs);

    let (pres, db) = zkp::present(
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
        db,
    )
    .await;

    println!("Success!");

    println!("{json:#}");

    Ok(())
}
