use std::collections::HashMap;

use oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Term};
use oxttl::NTriplesParser;
use rand::{prelude::StdRng, SeedableRng};
use rdf_proofs::{error::RDFProofsError, KeyGraph, VcPair, VerifiableCredential};
use regex::Regex;

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

const VC_1: &str = r#"
<did:example:john> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:john> <http://schema.org/name> "John Smith" .
<did:example:john> <http://example.org/vocab/isPatientOf> _:b0 .
<did:example:john> <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/lotNumber> "0000001" .
_:b0 <http://example.org/vocab/vaccinationDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/a> .
_:b0 <http://example.org/vocab/vaccine> <http://example.org/vaccine/b> .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:b1 <http://schema.org/name> "ABC inc." .
<http://example.org/vcred/00> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:john> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<http://example.org/vcred/00> <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;

const VC_PROOF_1: &str = r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#cryptosuite> "bbs-termwise-signature-2023" .
_:b0 <http://purl.org/dc/terms/created> "2023-02-09T09:35:07Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

const DISCLOSED_VC_1_WITH_HIDDEN_LITERALS: &str = r#"
_:e0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
_:e0 <http://schema.org/name> "John Smith" .
_:e0 <http://example.org/vocab/isPatientOf> _:b0 .
_:e0 <http://schema.org/worksFor> _:b1 .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://example.org/vocab/Vaccination> .
_:b0 <http://example.org/vocab/vaccine> _:e1 .
_:b0 <http://example.org/vocab/vaccinationDate> _:e5 .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Organization> .
_:e2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:e2 <https://www.w3.org/2018/credentials#credentialSubject> _:e0 .
_:e2 <https://www.w3.org/2018/credentials#issuer> <did:example:issuer0> .
_:e2 <https://www.w3.org/2018/credentials#issuanceDate> "2022-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:e2 <https://www.w3.org/2018/credentials#expirationDate> "2025-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
"#;

const DISCLOSED_VC_PROOF_1: &str = r#"
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

fn get_example_deanon_map_string() -> HashMap<String, String> {
    DEANON_MAP
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub(crate) fn get_term_from_string(term_string: &str) -> Result<Term, RDFProofsError> {
    let re_iri = Regex::new(r"^<([^>]+)>$")?;
    let re_blank_node = Regex::new(r"^_:(.+)$")?;
    let re_simple_literal = Regex::new(r#"^"([^"]+)"$"#)?;
    let re_typed_literal = Regex::new(r#"^"([^"]+)"\^\^<([^>]+)>$"#)?;
    let re_literal_with_langtag = Regex::new(r#"^"([^"]+)"@(.+)$"#)?;

    if let Some(caps) = re_iri.captures(term_string) {
        Ok(NamedNode::new_unchecked(&caps[1]).into())
    } else if let Some(caps) = re_blank_node.captures(term_string) {
        Ok(BlankNode::new_unchecked(&caps[1]).into())
    } else if let Some(caps) = re_simple_literal.captures(term_string) {
        Ok(Literal::new_simple_literal(&caps[1]).into())
    } else if let Some(caps) = re_typed_literal.captures(term_string) {
        Ok(Literal::new_typed_literal(&caps[1], NamedNode::new_unchecked(&caps[2])).into())
    } else if let Some(caps) = re_literal_with_langtag.captures(term_string) {
        Ok(Literal::new_language_tagged_literal(&caps[1], &caps[2])?.into())
    } else {
        Err(RDFProofsError::TtlTermParse(term_string.to_string()))
    }
}

fn get_deanon_map_from_string(
    deanon_map_string: &HashMap<String, String>,
) -> Result<HashMap<NamedOrBlankNode, Term>, RDFProofsError> {
    deanon_map_string
        .iter()
        .map(|(k, v)| {
            let key: NamedOrBlankNode = match get_term_from_string(k)? {
                Term::NamedNode(n) => Ok(n.into()),
                Term::BlankNode(n) => Ok(n.into()),
                Term::Literal(_) => Err(RDFProofsError::InvalidDeanonMapFormat(k.to_string())),
            }?;
            let value = get_term_from_string(v)?;
            Ok((key, value))
        })
        .collect()
}

fn get_example_deanon_map() -> HashMap<NamedOrBlankNode, Term> {
    get_deanon_map_from_string(&get_example_deanon_map_string()).unwrap()
}

pub fn get_graph_from_ntriples(ntriples: &str) -> Result<Graph, RDFProofsError> {
    let iter = NTriplesParser::new()
        .for_reader(ntriples.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Graph::from_iter(iter))
}

const DEANON_MAP_WITH_HIDDEN_LITERAL: [(&str, &str); 2] = [
    ("_:e4", "\"John Smith\""),
    (
        "_:e5",
        "\"2022-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>",
    ),
];
fn get_example_deanon_map_string_with_hidden_literal() -> HashMap<String, String> {
    DEANON_MAP_WITH_HIDDEN_LITERAL
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
fn get_example_deanon_map_with_hidden_literal() -> HashMap<NamedOrBlankNode, Term> {
    get_deanon_map_from_string(&get_example_deanon_map_string_with_hidden_literal()).unwrap()
}

#[test]
fn derive_and_verify_proof_with_hidden_literals() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let key_graph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).unwrap().into();

    let mut deanon_map = get_example_deanon_map();
    deanon_map.extend(get_example_deanon_map_with_hidden_literal());

    let vc_doc = get_graph_from_ntriples(VC_1).unwrap();
    let vc_proof_config = get_graph_from_ntriples(VC_PROOF_1).unwrap();
    let mut vc = VerifiableCredential::new(vc_doc, vc_proof_config);
    rdf_proofs::sign(&mut rng, &mut vc, &key_graph).unwrap();

    let disclosed_vc_doc = get_graph_from_ntriples(DISCLOSED_VC_1_WITH_HIDDEN_LITERALS).unwrap();
    let disclosed_vc_proof_config = get_graph_from_ntriples(DISCLOSED_VC_PROOF_1).unwrap();
    let disclosed_vc = VerifiableCredential::new(disclosed_vc_doc, disclosed_vc_proof_config);

    let vc_with_disclosed = VcPair::new(vc, disclosed_vc);
    let vcs = vec![vc_with_disclosed];

    let challenge = "abcde";

    let derived_proof = rdf_proofs::derive_proof(
        &mut rng,
        &vcs,
        &deanon_map,
        &key_graph,
        Some(challenge),
        None,
        None,
        None,
        None,
        vec![],
        HashMap::new(),
        None,
        None,
        None,
    )
    .unwrap();

    let verified = rdf_proofs::verify_proof(
        &mut rng,
        &derived_proof,
        &key_graph,
        Some(challenge),
        None,
        HashMap::new(),
        None,
        None,
    );

    assert!(verified.is_ok(), "{:?}", verified);

    println!("derived_proof: {}", rdf_canon::serialize(&derived_proof));
}
