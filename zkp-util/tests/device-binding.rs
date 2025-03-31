use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{biginteger::BigInteger, PrimeField};
use ark_secp256r1::Fq;
use ark_std::UniformRand;
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::DateTime;
use equality_across_groups::ec::commitments::from_base_field_to_scalar_field;
use kvac::bbs_sharp::ecdsa;
use rdf_util::oxrdf::vocab::xsd;
use rdf_util::{ObjectId, Value as RdfValue};
use std::{collections::BTreeMap, str::FromStr};
use zkp_util::{
    circuits::{self, GREATER_THAN_PUBLIC_ID, LESS_THAN_PUBLIC_ID},
    device_binding::{BlsFr, SecpFr},
    vc::{
        issuance::issue,
        presentation::present,
        requirements::{self, DeviceBindingRequirement, DeviceBindingVerificationParams},
        verification::verify,
    },
    SECP_GEN,
};

#[test]
fn device_binding() {
    let mut rng = rand_core::OsRng;

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
            (
                "https://schema.org/birthDate".into(),
                RdfValue::Typed(
                    "1990-01-01T00:00:00Z".into(),
                    "http://www.w3.org/2001/XMLSchema#dateTime".into(),
                ),
            ),
            (
                "https://example.org/coolness".into(),
                RdfValue::Typed("10000".into(), xsd::INTEGER.as_str().into()),
            ),
        ]),
        ObjectId::None,
    );

    // Device binding
    let secret_key = SecpFr::rand(&mut rng);
    let public_key = (SECP_GEN * secret_key).into_affine();

    let db = {
        let x: BlsFr = from_base_field_to_scalar_field::<Fq, BlsFr>(public_key.x().unwrap());
        let y: BlsFr = from_base_field_to_scalar_field::<Fq, BlsFr>(public_key.y().unwrap());

        let x_bytes_le = x.into_bigint().to_bytes_le();
        let y_bytes_le = y.into_bigint().to_bytes_le();

        (
            BASE64_STANDARD.encode(x_bytes_le),
            BASE64_STANDARD.encode(y_bytes_le),
        )
    };

    let message = SecpFr::rand(&mut rng);
    let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

    let comm_key_secp = b"comm-key-secp";
    let comm_key_tom = b"comm-key-tom";
    let comm_key_bls = b"comm-key-bls";
    let bpp_setup_label = b"bpp-setup";
    let merlin_transcript_label = b"transcript";
    let challenge_label = b"challenge";

    let vc = issue(
        &mut rng,
        claims,
        ISSUER_PK,
        ISSUER_SK,
        ISSUER_ID,
        ISSUER_KEY_ID,
        Some(DateTime::from_str("2020-01-01T00:00:00Z").unwrap()),
        Some(DateTime::from_str("2025-01-01T00:00:00Z").unwrap()),
        Some(DateTime::from_str("2030-01-01T00:00:00Z").unwrap()),
        Some(db),
    )
    .unwrap();

    println!("issuance done! {vc}");

    let requirements = vec![
        requirements::ProofRequirement::Required {
            key: "https://schema.org/name".into(),
        },
        requirements::ProofRequirement::Circuit {
            id: LESS_THAN_PUBLIC_ID.to_string(),
            private_var: "a".to_string(),
            private_key: "https://schema.org/birthDate".to_string(),

            public_var: "b".to_string(),
            public_val: RdfValue::Typed(
                "2001-01-01T00:00:00Z".into(),
                "http://www.w3.org/2001/XMLSchema#dateTime".into(),
            ),
        },
        requirements::ProofRequirement::Circuit {
            id: GREATER_THAN_PUBLIC_ID.to_string(),
            private_var: "a".to_string(),
            private_key: "https://example.org/coolness".to_string(),
            public_var: "b".to_string(),
            public_val: RdfValue::Typed("9999".into(), xsd::INTEGER.as_str().into()),
        },
    ];

    let db_requirement = DeviceBindingRequirement {
        public_key,
        message,
        message_signature,
        comm_key_secp_label: comm_key_secp.to_vec(),
        comm_key_tom_label: comm_key_tom.to_vec(),
        comm_key_bls_label: comm_key_bls.to_vec(),
        bpp_setup_label: bpp_setup_label.to_vec(),
        merlin_transcript_label,
        challenge_label,
    };

    let circuits = circuits::generate_circuits(&mut rng, &requirements);

    let vp = present(
        &mut rng,
        vc,
        &requirements,
        Some(db_requirement),
        &circuits.proving_keys,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    let db_verification = DeviceBindingVerificationParams {
        message,
        comm_key_secp_label: comm_key_secp.to_vec(),
        comm_key_tom_label: comm_key_tom.to_vec(),
        comm_key_bls_label: comm_key_bls.to_vec(),
        bpp_setup_label: bpp_setup_label.to_vec(),
        merlin_transcript_label,
        challenge_label,
    };

    let body = verify(
        &mut rng,
        vp,
        &requirements,
        Some(db_verification),
        &circuits.verifying_keys,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    println!("{body:#}")
}
