use std::fmt;

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
}

impl fmt::Debug for DeviceBindingRequirement {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Foo")
            .field("public_key", &self.public_key)
            .field("message", &self.message)
            .field(
                "message_signature",
                &format_args!(
                    "x: {}, response: {}",
                    self.message_signature.rand_x_coord, self.message_signature.response
                ),
            )
            .field("comm_key_secp_label", &self.comm_key_secp_label)
            .field("comm_key_tom_label", &self.comm_key_tom_label)
            .field("comm_key_bls_label", &self.comm_key_bls_label)
            .field("bpp_setup_label", &self.bpp_setup_label)
            .finish()
    }
}

impl Clone for DeviceBindingRequirement {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            message: self.message.clone(),
            message_signature: ecdsa::Signature {
                rand_x_coord: self.message_signature.rand_x_coord.clone(),
                response: self.message_signature.response.clone(),
            },
            comm_key_secp_label: self.comm_key_secp_label.clone(),
            comm_key_tom_label: self.comm_key_tom_label.clone(),
            comm_key_bls_label: self.comm_key_bls_label.clone(),
            bpp_setup_label: self.bpp_setup_label.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceBindingVerificationParams {
    pub message: SecpFr,
    pub comm_key_secp_label: Vec<u8>,
    pub comm_key_tom_label: Vec<u8>,
    pub comm_key_bls_label: Vec<u8>,
    pub bpp_setup_label: Vec<u8>,
}
