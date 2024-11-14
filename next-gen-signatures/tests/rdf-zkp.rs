use std::collections::HashMap;

use ark_bls12_381::Bls12_381;
use legogroth16::circom::CircomCircuit;
use legogroth16::circom::R1CS as R1CSOrig;
use multibase::Base;
use oxrdf::Graph;
use oxttl::NTriplesParser;
use rand::{prelude::StdRng, SeedableRng};
use rdf_proofs::{
    ark_to_base64url, derive_proof_string, error::RDFProofsError, verify_proof_string,
    CircuitString, KeyGraph, VcPairString, VerifiableCredential,
};

pub type R1CS = R1CSOrig<Bls12_381>;

const KEY_GRAPH: &str = r#"
# issuer0
<did:example:issuer0> <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
<did:example:issuer0#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer0> .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z4893E1L7AeYfqaduUdLYgcxefWAah8gJB8RhPi7JHQkdRbe" .
<did:example:issuer0#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC77BjGcGDVWfBdgzqwzp3uuWkoWuRMe8pnx4dkncia5t9LKHVt96BPGBizeSU7BKiV35h1tsuVwHUVt4arZuckxGCb2tTsB3fsY66mQNs5Bwoac2w2iyYFe8uenBUYdAiveEr" .
# issuer1
<did:example:issuer1> <https://w3id.org/security#verificationMethod> <did:example:issuer1#bls12_381-g2-pub001> .
<did:example:issuer1#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer1> .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z488yTRFj1e7W6s6MVN6iYm6taiNByQwSCg2XwgEJvAcXr15" .
<did:example:issuer1#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC7HaSjNELSGG8QnYdMvNurgfWfdGNo1Znqds6CoYQ24qKKWogiLtKWPoCLJapEYdKAMN9r6bdF9MeNrfV3fhUzkKwrfUewD5yVhwSVpM4tjv87YVgWGRTUuesxf7scabbPAnD" .
# issuer2
<did:example:issuer2> <https://w3id.org/security#verificationMethod> <did:example:issuer2#bls12_381-g2-pub001> .
<did:example:issuer2#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer2> .
<did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z489AEiC5VbeLmVZxokiJYkXNZrMza9eCiPZ51ekgcV9mNvG" .
<did:example:issuer2#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC7DKvfSfydgg48FpP53HgsLfWrVHfrmUXbwvw8AnSgW1JiA5741mwe3hpMNNRMYh3BgR9ebxvGAxPxFhr8F3jQHZANqb3if2MycjQN3ZBSWP3aGoRyat294icdVMDhTqoKXeJ" .
# issuer3
<did:example:issuer3> <https://w3id.org/security#verificationMethod> <did:example:issuer3#bls12_381-g2-pub001> .
<did:example:issuer3#bls12_381-g2-pub001> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#Multikey> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#controller> <did:example:issuer3> .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#secretKeyMultibase> "z488w754KqucDkNxCWCoi5DkH6pvEt6aNZNYYYoKmDDx8m5G" .
<did:example:issuer3#bls12_381-g2-pub001> <https://w3id.org/security#publicKeyMultibase> "zUC74KLKQtdApVyY3EbAZfiW6A7HdwSZVLsBF2vs5512YwNWs5PRYiqavzWLoiAq6UcKLv6RAnUM9Y117Pg4LayaBMa9euz23C2TDtBq8QuhpbDRDqsjUxLS5S9ruWRk71SEo69" .
"#;

const VC: &str = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:b0 .
<did:example:john> <http://schema.org/worksFor> _:b1 .
<did:example:john> <http://example.org/vocab/isTestOf> _:b2 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/lotNumber> "0000001" .
_:b0 <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:b1 <http://schema.org/name> "ABC inc." .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/CoolNumber> .
_:b2 <http://schema.org/Number> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
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
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:e0 <http://schema.org/name> _:e4 .
_:e0 <http://example.org/vocab/isPatientOf> _:b0 .
_:e0 <http://schema.org/worksFor> _:b1 .
_:e0 <http://example.org/vocab/isTestOf> _:b2 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/vaccine> _:e1 .
_:b0 <http://example.org/vocab/vaccinationDate> _:e5 .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/CoolNumber> .
_:b2 <http://schema.org/Number> _:e6 .
_:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
_:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;

const DISCLOSED_VC_PROOF_CONFIG: &str = r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

const DEANON_MAP: [(&str, &str); 4] = [
    ("_:e0", "<did:example:john>"),
    ("_:e1", "<http://example.org/vaccine/a>"),
    ("_:e2", "<http://example.org/vcred/00>"),
    ("_:e3", "<http://example.org/vicred/a>"),
];

const DEANON_MAP_WITH_HIDDEN_LITERAL: [(&str, &str); 3] = [
    ("_:e4", "\"John Smith\""),
    (
        "_:e5",
        "\"2022-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>",
    ),
    (
        "_:e6",
        "\"1337\"^^<http://www.w3.org/2001/XMLSchema#integer>",
    ),
];

fn get_deanon_map_string(map: &[(&str, &str)]) -> HashMap<String, String> {
    map.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn get_graph_from_ntriples(ntriples: &str) -> Result<Graph, RDFProofsError> {
    let iter = NTriplesParser::new()
        .for_reader(ntriples.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Graph::from_iter(iter))
}

#[test]
fn rdf_zkp() {
    let mut rng = StdRng::seed_from_u64(0u64);

    let vc_doc = get_graph_from_ntriples(VC).unwrap();
    let vc_proof_config = get_graph_from_ntriples(VC_PROOF).unwrap();
    let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

    let mut vc = VerifiableCredential::new(vc_doc, vc_proof_config);
    rdf_proofs::sign(&mut rng, &mut vc, &key_graph).unwrap();

    let vc_pairs = vec![VcPairString::new(
        &vc.document.to_string(),
        &vc.proof.to_string(),
        DISCLOSED_VC_WITH_HIDDEN_LITERALS,
        DISCLOSED_VC_PROOF_CONFIG,
    )];

    let mut deanon_map = get_deanon_map_string(&DEANON_MAP);
    deanon_map.extend(get_deanon_map_string(&DEANON_MAP_WITH_HIDDEN_LITERAL));

    // define predicates
    let predicates = vec![
            r#"
            _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
            _:b0 <https://zkp-ld.org/security#circuit> <https://zkp-ld.org/circuit/lessThanPubPrv> .
            _:b0 <https://zkp-ld.org/security#private> _:b1 .
            _:b0 <https://zkp-ld.org/security#public> _:b3 .
            _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
            _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
            _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
            _:b2 <https://zkp-ld.org/security#var> "greater" .
            _:b2 <https://zkp-ld.org/security#val> _:e5 .
            _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
            _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
            _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
            _:b4 <https://zkp-ld.org/security#var> "lesser" .
            _:b4 <https://zkp-ld.org/security#val> "2000-12-31T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            "#.to_string(),
            r#"
            _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#Predicate> .
            _:b0 <https://zkp-ld.org/security#circuit> <https://zkp-ld.org/circuit/alexey/lessThanPublic> .
            _:b0 <https://zkp-ld.org/security#private> _:b1 .
            _:b0 <https://zkp-ld.org/security#public> _:b3 .
            _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b2 .
            _:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
            _:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PrivateVariable> .
            _:b2 <https://zkp-ld.org/security#var> "a" .
            _:b2 <https://zkp-ld.org/security#val> _:e6 .
            _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> _:b4 .
            _:b3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil> .
            _:b4 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://zkp-ld.org/security#PublicVariable> .
            _:b4 <https://zkp-ld.org/security#var> "b" .
            _:b4 <https://zkp-ld.org/security#val> "9999"^^<http://www.w3.org/2001/XMLSchema#integer> .
            "#.to_string(),
        ];

    // define circuit
    let circuit_r1cs_1 = R1CS::from_file("circom/bls12381/less_than_pub_prv_64.r1cs").unwrap();
    let circuit_wasm_1 = std::fs::read("circom/bls12381/less_than_pub_prv_64.wasm").unwrap();
    let commit_witness_count_1 = 1;
    let snark_proving_key_1 = CircomCircuit::setup(circuit_r1cs_1.clone())
        .generate_proving_key(commit_witness_count_1, &mut rng)
        .unwrap();

    // serialize to multibase
    let circuit_r1cs_1 = ark_to_base64url(&circuit_r1cs_1).unwrap();
    let circuit_wasm_1 = multibase::encode(Base::Base64Url, circuit_wasm_1);
    let snark_proving_key_string_1 = ark_to_base64url(&snark_proving_key_1).unwrap();
    let snark_verifying_key_string_1 = ark_to_base64url(&snark_proving_key_1.vk).unwrap();

    // define circuit
    let circuit_r1cs_2 = R1CS::from_file("circom/bls12381/less_than_public_64.r1cs").unwrap();
    let circuit_wasm_2 = std::fs::read("circom/bls12381/less_than_public_64.wasm").unwrap();
    let commit_witness_count_2 = 1;
    let snark_proving_key_2 = CircomCircuit::setup(circuit_r1cs_2.clone())
        .generate_proving_key(commit_witness_count_2, &mut rng)
        .unwrap();

    // serialize to multibase
    let circuit_r1cs_2 = ark_to_base64url(&circuit_r1cs_2).unwrap();
    let circuit_wasm_2 = multibase::encode(Base::Base64Url, circuit_wasm_2);
    let snark_proving_key_string_2 = ark_to_base64url(&snark_proving_key_2).unwrap();
    let snark_verifying_key_string_2 = ark_to_base64url(&snark_proving_key_2.vk).unwrap();

    // generate SNARK proving key (by Verifier)
    let circuit = HashMap::from([
        (
            "https://zkp-ld.org/circuit/lessThanPubPrv".to_string(),
            CircuitString {
                circuit_r1cs: circuit_r1cs_1.clone(),
                circuit_wasm: circuit_wasm_1.clone(),
                snark_proving_key: snark_proving_key_string_1.clone(),
            },
        ),
        (
            "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
            CircuitString {
                circuit_r1cs: circuit_r1cs_2.clone(),
                circuit_wasm: circuit_wasm_2.clone(),
                snark_proving_key: snark_proving_key_string_2.clone(),
            },
        ),
    ]);

    let derived_proof = derive_proof_string(
        &mut rng,
        &vc_pairs,
        &deanon_map,
        KEY_GRAPH,
        None,
        None,
        None,
        None,
        None,
        Some(&predicates),
        Some(&circuit),
    )
    .unwrap();

    let snark_verifying_keys = HashMap::from([
        (
            "https://zkp-ld.org/circuit/lessThanPubPrv".to_string(),
            snark_verifying_key_string_1.clone(),
        ),
        (
            "https://zkp-ld.org/circuit/alexey/lessThanPublic".to_string(),
            snark_verifying_key_string_2.clone(),
        ),
    ]);

    let verified = verify_proof_string(
        &mut rng,
        &derived_proof,
        KEY_GRAPH,
        None,
        None,
        Some(snark_verifying_keys.clone()),
    );
    assert!(verified.is_ok(), "{:?}", verified);

    println!("derive_proof: {}", derived_proof);
}
