use ark_bls12_381::Bls12_381;
use legogroth16::circom::{r1cs::R1CSFile, CircomCircuit, R1CS as R1CSOrig};
use multibase::Base;
use rand::RngCore;
use rdf_proofs::{ark_to_base64url, CircuitString};
use std::{collections::HashMap, io::Cursor};

use super::{Circuits, ProofRequirement};

type R1CS = R1CSOrig<Bls12_381>;

pub const LESS_THAN_PUBLIC_ID: &str = "https://zkp-ld.org/circuit/ubique/lessThanPublic";
const LESS_THAN_PUBLIC_R1CS: &[u8] =
    include_bytes!("../../../circom/bls12381/less_than_public_64.r1cs");
const LESS_THAN_PUBLIC_WASM: &[u8] =
    include_bytes!("../../../circom/bls12381/less_than_public_64.wasm");

pub fn get_circuit_defs() -> HashMap<String, (&'static [u8], &'static [u8])> {
    HashMap::from([(
        LESS_THAN_PUBLIC_ID.to_string(),
        (LESS_THAN_PUBLIC_R1CS, LESS_THAN_PUBLIC_WASM),
    )])
}

pub fn generate_circuits<R: RngCore>(rng: &mut R, reqs: &Vec<ProofRequirement>) -> Circuits {
    let lookup = get_circuit_defs();

    let mut verifying_keys = HashMap::<String, String>::new();
    let mut proving_keys = HashMap::<String, String>::new();

    for req in reqs {
        if let ProofRequirement::Circuit { id, .. } = req {
            let (r1cs, _) = lookup.get(id).unwrap();
            let r1cs: R1CS = R1CSFile::new(Cursor::new(r1cs)).unwrap().into();

            let commit_witness_count = 1;
            let snark_proving_key = CircomCircuit::setup(r1cs)
                .generate_proving_key(commit_witness_count, rng)
                .unwrap();

            // serialize to multibase
            let snark_proving_key_string = ark_to_base64url(&snark_proving_key).unwrap();
            let snark_verifying_key_string = ark_to_base64url(&snark_proving_key.vk).unwrap();

            verifying_keys.insert(id.clone(), snark_verifying_key_string);
            proving_keys.insert(id.clone(), snark_proving_key_string);
        }
    }

    Circuits {
        verifying_keys,
        proving_keys,
    }
}

pub fn load_circuits(keys: &HashMap<String, String>) -> HashMap<String, CircuitString> {
    type R1CS = R1CSOrig<Bls12_381>;

    let lookup = get_circuit_defs();
    let mut circuits = HashMap::<String, CircuitString>::new();

    for (id, key) in keys {
        let (r1cs, wasm) = lookup.get(id).unwrap();
        let r1cs: R1CS = R1CSFile::new(Cursor::new(r1cs)).unwrap().into();

        let wasm = multibase::encode(Base::Base64Url, wasm);
        let r1cs = ark_to_base64url(&r1cs).unwrap();

        let circuit = CircuitString {
            circuit_r1cs: r1cs,
            circuit_wasm: wasm,
            snark_proving_key: key.clone(),
        };

        circuits.insert(id.clone(), circuit);
    }

    circuits
}
