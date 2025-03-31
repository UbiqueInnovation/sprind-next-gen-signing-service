use kvac::bbs_sharp::ecdsa;
use rdf_util::Value as RdfValue;
use serde::{Deserialize, Serialize};

use crate::device_binding::{SecpAffine, SecpFr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValue {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofRequirement {
    Required {
        key: String,
    },
    Circuit {
        id: String,

        private_var: String,
        private_key: String,

        public_var: String,
        public_val: RdfValue,
    },
}

pub struct DeviceBindingRequirement {
    pub public_key: SecpAffine,
    pub message: SecpFr,
    pub message_signature: ecdsa::Signature,
    pub comm_key_secp_label: Vec<u8>,
    pub comm_key_tom_label: Vec<u8>,
    pub comm_key_bls_label: Vec<u8>,
    pub bpp_setup_label: Vec<u8>,
    pub merlin_transcript_label: &'static [u8],
    pub challenge_label: &'static [u8],
}

pub struct DeviceBindingVerificationParams {
    pub message: SecpFr,
    pub comm_key_secp_label: Vec<u8>,
    pub comm_key_tom_label: Vec<u8>,
    pub comm_key_bls_label: Vec<u8>,
    pub bpp_setup_label: Vec<u8>,
    pub merlin_transcript_label: &'static [u8],
    pub challenge_label: &'static [u8],
}
