use std::collections::{BTreeSet, HashMap};

use ark_bls12_381::Bls12_381;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_secp256r1::Fq;
use ark_std::UniformRand;
use base64::{prelude::BASE64_STANDARD, Engine};
use equality_across_groups::ec::commitments::from_base_field_to_scalar_field;
use kvac::bbs_sharp::ecdsa;
use legogroth16::circom::CircomCircuit;
use legogroth16::circom::R1CS as R1CSOrig;
use multibase::Base;
use proof_system::prelude::{
    ped_comm::PedersenCommitment, EqualWitnesses, MetaStatements, Statements, Witness, Witnesses,
};
use rand_core::OsRng;
use rdf_proofs::{
    ark_to_base64url, error::RDFProofsError, verify_proof_string, CircuitString, KeyGraph,
    VcPairString, VerifiableCredential,
};
use rdf_util::oxrdf::{Graph, NamedNode, Subject};
use zkp_util::{
    device_binding::{BlsFr, DeviceBinding, SecpFr},
    SECP_GEN,
};

pub type R1CS = R1CSOrig<Bls12_381>;

const KEY_GRAPH: &str = r#"
# issuer0
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
"#;

const VC: &str = r#"
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://example.org/deviceBinding> _:b0 .
_:b0 <https://example.org/deviceBinding#x> "xvalue"^^<http://www.w3.org/2001/XMLSchema#base64BytesLe> .
_:b0 <https://example.org/deviceBinding#y> "yvalue"^^<http://www.w3.org/2001/XMLSchema#base64BytesLe> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;

const VC_PROOF: &str = r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

const DISCLOSED_VC_WITH_HIDDEN_LITERALS: &str = r#"
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://example.org/deviceBinding> _:b0 .
_:b0 <https://example.org/deviceBinding#x> _:d0 .
_:b0 <https://example.org/deviceBinding#y> _:d1 .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;

const DISCLOSED_VC_PROOF_CONFIG: &str = r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

const DEANON_MAP: [(&str, &str); 0] = [
    // ("_:e0", "<did:example:john>"),
    // ("_:e1", "<http://example.org/vaccine/a>"),
    // ("_:e2", "<http://example.org/vcred/00>"),
    // ("_:e3", "<http://example.org/vicred/a>"),
];

const DEANON_MAP_WITH_HIDDEN_LITERAL: [(&str, &str); 0] = [
    // ("_:e4", "\"John Smith\""),
    // (
    //     "_:e5",
    //     "\"2022-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>",
    // ),
    // (
    //     "_:e6",
    //     "\"1337\"^^<http://www.w3.org/2001/XMLSchema#integer>",
    // ),
];

fn get_deanon_map_string(map: &[(&str, &str)]) -> HashMap<String, String> {
    map.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn get_graph_from_ntriples(ntriples: &str) -> Result<Graph, RDFProofsError> {
    Ok(rdf_util::from_str(ntriples).unwrap().to_graph(None))
}

#[test]
fn device_binding_test() {
    let mut rng = OsRng;

    // Device binding
    let secret_key = SecpFr::rand(&mut rng);
    let public_key = (SECP_GEN * secret_key).into_affine();

    let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(public_key.x().unwrap());
    let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(public_key.y().unwrap());

    let (b64_x, b64_y) = {
        let x_bytes = pk_x.into_bigint().to_bytes_le();
        let y_bytes = pk_y.into_bigint().to_bytes_le();

        (
            BASE64_STANDARD.encode(x_bytes),
            BASE64_STANDARD.encode(y_bytes),
        )
    };

    let vc = VC.replace("xvalue", &b64_x).replace("yvalue", &b64_y);

    let message = SecpFr::rand(&mut rng);
    let message_signature = ecdsa::Signature::new_prehashed(&mut rng, message, secret_key);

    let comm_key_secp = b"comm-key-secp";
    let comm_key_tom = b"comm-key-tom";
    let comm_key_bls = b"comm-key-bls";
    let bpp_setup_label = b"bpp-setup";
    let merlin_transcript_label = b"transcript";
    let challenge_label = b"challenge";

    let db = DeviceBinding::new(
        &mut rng,
        public_key,
        message,
        message_signature,
        comm_key_secp,
        comm_key_tom,
        comm_key_bls,
        bpp_setup_label,
        merlin_transcript_label,
        challenge_label,
    )
    .unwrap();

    let vc_doc = get_graph_from_ntriples(&vc).unwrap();
    let vc_proof_config = get_graph_from_ntriples(VC_PROOF).unwrap();
    let key_graph: KeyGraph = rdf_util::from_str_with_hint(
        KEY_GRAPH,
        Subject::NamedNode(NamedNode::new_unchecked("did:example:issuer0")),
    )
    .unwrap()
    .to_graph(None)
    .into();

    let mut vc = VerifiableCredential::new(vc_doc, vc_proof_config);
    rdf_proofs::sign(&mut rng, &mut vc, &key_graph).unwrap();

    let vc_pairs = vec![VcPairString::new(
        &vc.document.to_string(),
        &vc.proof.to_string(),
        DISCLOSED_VC_WITH_HIDDEN_LITERALS,
        DISCLOSED_VC_PROOF_CONFIG,
    )];

    // let mut deanon_map = get_deanon_map_string(&DEANON_MAP);
    // deanon_map.extend(get_deanon_map_string(&DEANON_MAP_WITH_HIDDEN_LITERAL));
    let deanon_map = HashMap::from([
        (
            "_:d0".into(),
            format!("\"{b64_x}\"^^<http://www.w3.org/2001/XMLSchema#base64BytesLe>"),
        ),
        (
            "_:d1".into(),
            format!("\"{b64_y}\"^^<http://www.w3.org/2001/XMLSchema#base64BytesLe>"),
        ),
    ]);

    // define predicates
    // let predicates = vec![
    //     r#"
    //     _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
    //     _:b0 <https://zkp-ld.org/security#circuit> <https://zkp-ld.org/circuit/lessThanPubPrv> .
    //     _:b0 <https://zkp-ld.org/security#private> _:b1 .
    //     _:b0 <https://zkp-ld.org/security#public> _:b3 .
    //     _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
    //     _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
    //     _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
    //     _:b2 <https://zkp-ld.org/security#var> "greater" .
    //     _:b2 <https://zkp-ld.org/security#val> _:e5 .
    //     _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
    //     _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
    //     _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
    //     _:b4 <https://zkp-ld.org/security#var> "lesser" .
    //     _:b4 <https://zkp-ld.org/security#val> "2000-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
    //     "#.to_string(),
    //     r#"
    //     _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
    //     _:b0 <https://zkp-ld.org/security#circuit> <https://zkp-ld.org/circuit/alexey/lessThanPublic> .
    //     _:b0 <https://zkp-ld.org/security#private> _:b1 .
    //     _:b0 <https://zkp-ld.org/security#public> _:b3 .
    //     _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
    //     _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
    //     _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
    //     _:b2 <https://zkp-ld.org/security#var> "a" .
    //     _:b2 <https://zkp-ld.org/security#val> _:e6 .
    //     _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
    //     _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
    //     _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
    //     _:b4 <https://zkp-ld.org/security#var> "b" .
    //     _:b4 <https://zkp-ld.org/security#val> "9999"^^<http://www.w3.org/2001/XMLSchema#integer> .
    //     "#.to_string(),
    // ];

    // define circuit
    // let circuit_r1cs_1 = R1CS::from_file("circom/bls12381/less_than_pub_prv_64.r1cs").unwrap();
    // let circuit_wasm_1 = std::fs::read("circom/bls12381/less_than_pub_prv_64.wasm").unwrap();
    // let commit_witness_count_1 = 1;
    // let snark_proving_key_1 = CircomCircuit::setup(circuit_r1cs_1.clone())
    //     .generate_proving_key(commit_witness_count_1, &mut rng)
    //     .unwrap();

    // serialize to multibase
    // let circuit_r1cs_1 = ark_to_base64url(&circuit_r1cs_1).unwrap();
    // let circuit_wasm_1 = multibase::encode(Base::Base64Url, circuit_wasm_1);
    // let snark_proving_key_string_1 = ark_to_base64url(&snark_proving_key_1).unwrap();
    // let snark_verifying_key_string_1 = ark_to_base64url(&snark_proving_key_1.vk).unwrap();

    // define circuit
    // let circuit_r1cs_2 = R1CS::from_file("circom/bls12381/less_than_public_64.r1cs").unwrap();
    // let circuit_wasm_2 = std::fs::read("circom/bls12381/less_than_public_64.wasm").unwrap();
    // let commit_witness_count_2 = 1;
    // let snark_proving_key_2 = CircomCircuit::setup(circuit_r1cs_2.clone())
    //     .generate_proving_key(commit_witness_count_2, &mut rng)
    //     .unwrap();

    // serialize to multibase
    // let circuit_r1cs_2 = ark_to_base64url(&circuit_r1cs_2).unwrap();
    // let circuit_wasm_2 = multibase::encode(Base::Base64Url, circuit_wasm_2);
    // let snark_proving_key_string_2 = ark_to_base64url(&snark_proving_key_2).unwrap();
    // let snark_verifying_key_string_2 = ark_to_base64url(&snark_proving_key_2.vk).unwrap();

    // generate SNARK proving key (by Verifier)
    // let circuit = HashMap::from([
    //     (
    //         "https://zkp-ld.org/circuit/lessThanPubPrv".to_string(),
    //         CircuitString {
    //             circuit_r1cs: circuit_r1cs_1.clone(),
    //             circuit_wasm: circuit_wasm_1.clone(),
    //             snark_proving_key: snark_proving_key_string_1.clone(),
    //         },
    //     ),
    //     (
    //         "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
    //         CircuitString {
    //             circuit_r1cs: circuit_r1cs_2.clone(),
    //             circuit_wasm: circuit_wasm_2.clone(),
    //             snark_proving_key: snark_proving_key_string_2.clone(),
    //         },
    //     ),
    // ]);

    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();
    let mut witnesses = Witnesses::<Bls12_381>::new();

    statements.add(PedersenCommitment::new_statement_from_params(
        db.bls_comm_key.clone(),
        db.bls_comm_pk_x,
    ));

    statements.add(PedersenCommitment::new_statement_from_params(
        db.bls_comm_key.clone(),
        db.bls_comm_pk_y,
    ));

    meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([(0, 1 + 15 + 2), (1, 0)])));
    meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([(0, 1 + 18 + 2), (2, 0)])));

    witnesses.add(Witness::PedersenCommitment(db.bls_scalars_x.clone()));
    witnesses.add(Witness::PedersenCommitment(db.bls_scalars_y.clone()));

    let derived_proof = rdf_proofs::derive_proof_string(
        &mut rng,
        &vc_pairs,
        &deanon_map,
        KEY_GRAPH,
        None,
        None,
        None,
        None,
        None,
        None, // Some(&predicates),
        None, // Some(&circuit),
        Some(statements),
        Some(meta_statements),
        Some(witnesses),
        None,
    )
    .unwrap();

    // let snark_verifying_keys = HashMap::from([
    //     (
    //         "https://zkp-ld.org/circuit/lessThanPubPrv".to_string(),
    //         snark_verifying_key_string_1.clone(),
    //     ),
    //     (
    //         "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
    //         snark_verifying_key_string_2.clone(),
    //     ),
    // ]);

    let mut statements = Statements::<Bls12_381>::new();
    let mut meta_statements = MetaStatements::new();

    statements.add(PedersenCommitment::new_statement_from_params(
        db.bls_comm_key.clone(),
        db.bls_comm_pk_x,
    ));

    statements.add(PedersenCommitment::new_statement_from_params(
        db.bls_comm_key.clone(),
        db.bls_comm_pk_y,
    ));

    meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([(0, 1 + 15 + 2), (1, 0)])));
    meta_statements.add_witness_equality(EqualWitnesses(BTreeSet::from([(0, 1 + 18 + 2), (2, 0)])));

    let verified = verify_proof_string(
        &mut rng,
        &derived_proof,
        KEY_GRAPH,
        None,
        None,
        None, // Some(snark_verifying_keys.clone()),
        Some(statements),
        Some(meta_statements),
    );
    assert!(verified.is_ok(), "{:?}", verified);

    println!("derive_proof: {}", derived_proof);
}
