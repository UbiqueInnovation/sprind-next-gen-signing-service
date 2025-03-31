use rdf_proofs::{
    context::PROOF_VALUE, reorder_vc_triples, ProofWithIndexMap, VerifiableCredential,
    VerifiableCredentialTriples, VerifiablePresentation,
};
use rdf_util::oxrdf::{Dataset, NamedNode, Term};

pub fn index_of_vc(vc: &VerifiableCredential, value: &Term) -> usize {
    let terms = rdf_proofs::signature::transform(&vc.document).unwrap();

    terms.iter().position(|t| t == value).unwrap() + 1
}

pub fn index_of_vp(vp_dataset: &Dataset, predicate: &NamedNode) -> usize {
    let vp: VerifiablePresentation = vp_dataset.try_into().unwrap();

    // get proof value
    let proof_value_encoded = vp.get_proof_value().unwrap();

    // drop proof value from VP proof before canonicalization
    // (otherwise it could differ from the prover's canonicalization)
    let vp_without_proof_value = Dataset::from_iter(
        vp_dataset
            .iter()
            .filter(|q| !(q.predicate == PROOF_VALUE && q.graph_name == vp.proof_graph_name)),
    );

    // canonicalize VP
    let c14n_map_for_disclosed = rdf_util::canon::issue(&vp_without_proof_value).unwrap();
    let canonicalized_vp =
        rdf_util::canon::relabel(&vp_without_proof_value, &c14n_map_for_disclosed).unwrap();

    // decompose canonicalized VP into graphs
    let VerifiablePresentation {
        disclosed_vcs: c14n_disclosed_vc_graphs,
        ..
    } = (&canonicalized_vp).try_into().unwrap();

    // convert to Vecs
    let disclosed_vec = c14n_disclosed_vc_graphs
        .into_iter()
        .map(|(_, v)| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();

    // deserialize proof value into proof and index_map
    let (_, proof_value_bytes) = multibase::decode(proof_value_encoded).unwrap();
    let ProofWithIndexMap { index_map, .. } =
        ciborium::de::from_reader(proof_value_bytes.as_slice()).unwrap();

    // reorder statements according to index map
    let reordered_vc_triples = reorder_vc_triples(&disclosed_vec, &index_map).unwrap();

    let index: usize = reordered_vc_triples
        .iter()
        .next()
        .unwrap()
        .document
        .iter()
        .find_map(|(k, v)| {
            v.as_ref()
                .and_then(|v| (&v.predicate == predicate).then_some(3 * k + 1))
        })
        .unwrap();

    index + 1
}
