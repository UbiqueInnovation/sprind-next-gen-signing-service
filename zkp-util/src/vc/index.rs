/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

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
        .into_values()
        .map(|v| v.into())
        .collect::<Vec<VerifiableCredentialTriples>>();

    // deserialize proof value into proof and index_map
    let (_, proof_value_bytes) = multibase::decode(proof_value_encoded).unwrap();
    let ProofWithIndexMap { index_map, .. } =
        ciborium::de::from_reader(proof_value_bytes.as_slice()).unwrap();

    // reorder statements according to index map
    let reordered_vc_triples = reorder_vc_triples(&disclosed_vec, &index_map).unwrap();

    let index: usize = reordered_vc_triples
        .first()
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
