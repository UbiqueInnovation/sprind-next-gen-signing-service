use chrono::DateTime;
use rdf_util::oxrdf::vocab::xsd;
use rdf_util::{ObjectId, Value as RdfValue};
use serde_json::json;
use std::{collections::BTreeMap, str::FromStr};
use zkp_util::{
    circuits,
    vc::{issuance::issue, presentation::present, requirements, verification::verify},
};

#[test]
fn selective_disclosure() {
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
        None,
    )
    .unwrap();

    println!("issuance done! {}", vc.to_string());

    let requirements = vec![requirements::ProofRequirement::Required {
        key: "https://schema.org/name".into(),
    }];

    let circuits = circuits::generate_circuits(&mut rng, &requirements);

    let vp = present(
        &mut rng,
        vc,
        &requirements,
        None,
        &circuits.proving_keys,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    let body = verify(
        &mut rng,
        vp,
        &requirements,
        None,
        &circuits.verifying_keys,
        ISSUER_PK,
        ISSUER_ID,
        ISSUER_KEY_ID,
    )
    .unwrap();

    assert_eq!(
        body,
        json!({
            "https://schema.org/name": "John Doe"
        })
    );
}
