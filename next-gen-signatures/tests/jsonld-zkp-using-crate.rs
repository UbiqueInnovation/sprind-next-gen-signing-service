use std::io::Cursor;

use json_ld::{
    syntax::{Parse, Value},
    JsonLdProcessor, RemoteDocument, ReqwestLoader,
};
use oxrdf::{Dataset, Graph};
use oxttl::{NQuadsParser, NTriplesParser};
use rand::{prelude::StdRng, SeedableRng};
use rdf_proofs::{KeyGraph, VerifiableCredential};
use rdf_types::{
    generator,
    vocabulary::{IndexVocabulary, IriVocabularyMut},
};
use static_iref::iri;

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

const VC_PROOF_WITHOUT_PROOFVALUE_AND_DATETIME_1: &str = r#"
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:b0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:b0 <https://w3id.org/security#verificationMethod> <did:example:issuer0#bls12_381-g2-pub001> .
"#;

pub fn get_graph_from_ntriples(ntriples: &str) -> Graph {
    let iter = NTriplesParser::new()
        .for_reader(ntriples.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    Graph::from_iter(iter)
}

pub async fn canonicalize_jsonld(data: &str) -> Graph {
    let doc = RemoteDocument::new(None, None, Value::parse_str(data).unwrap().0);

    let mut vocabulary: IndexVocabulary = IndexVocabulary::new();
    vocabulary.insert(iri!("https://example.com/"));

    let loader = ReqwestLoader::new();

    let mut generator = generator::Blank::new_with_prefix("b".to_string());

    let mut rdf = doc.to_rdf(&mut generator, &loader).await.unwrap();

    let nquads = rdf
        .cloned_quads()
        .map(|q| format!("{} .", q.to_string()))
        .collect::<Vec<_>>()
        .join("\n");

    let input_quads = NQuadsParser::new()
        .for_reader(Cursor::new(nquads))
        .map(|x| x.unwrap());

    let input_dataset = Dataset::from_iter(input_quads);
    let canonicalized = rdf_canon::canonicalize(&input_dataset).unwrap();

    get_graph_from_ntriples(&canonicalized)
}

async fn issue(data: &str, _sk: ()) -> VerifiableCredential {
    // 1. Turn data into canonical form
    let canonicalized = canonicalize_jsonld(data).await;

    // 2. Sign data
    let keygraph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).into();
    let proof = get_graph_from_ntriples(VC_PROOF_WITHOUT_PROOFVALUE_AND_DATETIME_1);
    let mut vc = VerifiableCredential::new(canonicalized, proof);
    let mut rng = StdRng::seed_from_u64(0u64);

    rdf_proofs::sign(&mut rng, &mut vc, &keygraph).unwrap();

    vc
}

fn derive(vc: VerifiableCredential, _pres: &str) -> VerifiableCredential {
    // 1. Turn data into canonical form

    // 2. Create presentation

    vc
}

fn verify(_pk: (), vp: VerifiableCredential) -> bool {
    // 1. Turn data into canonical form

    // 2. Verify presentation
    let keygraph: KeyGraph = get_graph_from_ntriples(KEY_GRAPH).into();
    rdf_proofs::verify(&vp, &keygraph).is_ok()
}

#[tokio::test]
async fn jsonld_zkp_using_crate() {
    // In theory we have some data that we want to issue / present / verify
    let data = r#"
{
  "@context": "http://schema.org",
  "type": "Person",
  "name": "John Smith",
  "worksFor": {
    "type": "Organization",
    "name": "ABC inc."
  }
}
    "#;

    // There is a known issuer
    let (issuer_pk, issuer_sk) = ((), ());

    // 1. The issuer issues a credential
    let vc = issue(data, issuer_sk).await;
    println!("{vc}");

    // Now we want / need to present some data
    let pres_def = r#"
    {
        "givenName": {}
        "familyName": {}
    }
    "#;

    // 2. Create presentation
    let vp = derive(vc, pres_def);

    // 3. Now the issuer can verify the presentation
    assert!(verify(issuer_pk, vp));

    println!("Done!")
}
