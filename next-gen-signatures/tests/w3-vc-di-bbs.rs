#![allow(unused)]

/// https://www.w3.org/TR/vc-di-bbs/#create-base-proof-bbs-2023

pub type RDFGraph = oxrdf::Graph;
pub type JsonLDValue = json_ld::syntax::Value;

pub enum FeatureOption {
    /// Note that "baseline" is used to denote the case of no optional features.
    Baseline,
    AnonymousHolderBinding {
        commitment_with_proof: Option<Vec<u8>>,
    },
    PseudonymIssuerPid,
    PseudonymHiddenPid {
        commitment_with_proof: Option<Vec<u8>>,
    },
}

///  The following algorithm specifies how to generate a proof configuration from a set of proof options that is
/// used as input to the base proof hashing algorithm.
///
/// The required inputs to this algorithm are proof options (options). The proof options MUST contain a type
/// identifier for the cryptographic suite (type) and MUST contain a cryptosuite identifier (cryptosuite).
///
/// A proof configuration object is produced as output.
pub fn base_proof_configuration(options: JsonLDValue) -> JsonLDValue {
    todo!()
}

/// The following algorithm specifies how to create a data integrity proof given an unsecured data document.
///
/// Required inputs are an unsecured data document (map unsecuredDocument), a set of proof options (map options),
/// an array of mandatory JSON pointers (mandatoryPointers), a featureOption indicator parameter, and, depending
/// on the featureOption, a commitment_with_proof byte array.
///
/// A data integrity proof (map), or an error, is produced as output.
pub fn create_base_proof(
    unsecured_document: RDFGraph,
    options: JsonLDValue,
    mandatory_pointers: Vec<String>,
    feature_option: FeatureOption,
) -> JsonLDValue {
    // 1) Let proof be a clone of the proof options, options.
    let proof = options.clone();

    todo!("Implement create_base_proof")
}
