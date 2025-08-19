use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoEnumIterator};

use bitvm::{
    chunk::api::{PublicKeys as ApiPublicKeys, NUM_HASH, NUM_PUBS, NUM_U256},
    signatures::{
        signing_winternitz::{WinternitzPublicKey, WinternitzSecret, LOG_D},
        winternitz::Parameters,
        HASH_LEN,
    },
};

#[derive(
    Serialize, Deserialize, Eq, PartialEq, Hash, Clone, PartialOrd, Ord, Display, Debug, EnumIter,
)]
#[serde(into = "String", try_from = "String")]
pub enum CommitmentMessageId {
    // name of intermediate value and length of message
    Groth16IntermediateValues((String, usize)),
}

const VAL_SEPARATOR: char = '|';

impl From<CommitmentMessageId> for String {
    fn from(id: CommitmentMessageId) -> String {
        match id {
            CommitmentMessageId::Groth16IntermediateValues((variable_name, size)) => {
                format!(
                    "Groth16IntermediateValues{}{}{}{}",
                    VAL_SEPARATOR, variable_name, VAL_SEPARATOR, size
                )
            }
        }
    }
}

impl TryFrom<String> for CommitmentMessageId {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        for variant in CommitmentMessageId::iter() {
            if s == variant.to_string() {
                return Ok(variant);
            } else if s.starts_with(&format!("Groth16IntermediateValues{}", VAL_SEPARATOR)) {
                let parts: Vec<_> = s.split(VAL_SEPARATOR).collect();
                if parts.len() != 3 {
                    return Err(format!("Invalid Groth16IntermediateValues format: {}", s));
                }
                let variable_name = parts[1].to_string();
                let size = parts[2]
                    .parse::<usize>()
                    .map_err(|e| format!("Invalid size in Groth16IntermediateValues: {}", e))?;

                return Ok(CommitmentMessageId::Groth16IntermediateValues((
                    variable_name,
                    size,
                )));
            }
        }

        Err(format!("Unknown CommitmentMessageId: {}", s))
    }
}

impl CommitmentMessageId {
    pub fn pubkey_map_for_assert(
        raw_pubkeys: &ApiPublicKeys,
    ) -> HashMap<CommitmentMessageId, WinternitzPublicKey> {
        let mut commitment_map = HashMap::new();
        for i in 0..NUM_PUBS {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((format!("{}", i), 32)),
                WinternitzPublicKey {
                    public_key: raw_pubkeys.0[i].to_vec(),
                    parameters: Parameters::new_by_bit_length(8 * 32, LOG_D),
                },
            );
        }
        for i in 0..NUM_U256 {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((format!("{}", i + NUM_PUBS), 32)),
                WinternitzPublicKey {
                    public_key: raw_pubkeys.1[i].to_vec(),
                    parameters: Parameters::new_by_bit_length(8 * 32, LOG_D),
                },
            );
        }
        for i in 0..NUM_HASH {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((
                    format!("{}", i + NUM_PUBS + NUM_U256),
                    HASH_LEN as usize,
                )),
                WinternitzPublicKey {
                    public_key: raw_pubkeys.2[i].to_vec(),
                    parameters: Parameters::new_by_bit_length(8 * HASH_LEN as u32, LOG_D),
                },
            );
        }

        commitment_map
    }

    // btree map is a copy of chunker related commitments
    pub fn generate_commitment_secrets() -> HashMap<CommitmentMessageId, WinternitzSecret> {
        println!("Generating commitment secrets ...");
        let mut commitment_map = HashMap::new();

        for i in 0..NUM_PUBS {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((format!("{}", i), 32)),
                WinternitzSecret::new(32),
            );
        }
        for i in 0..NUM_U256 {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((format!("{}", i + NUM_PUBS), 32)),
                WinternitzSecret::new(32),
            );
        }
        for i in 0..NUM_HASH {
            commitment_map.insert(
                CommitmentMessageId::Groth16IntermediateValues((
                    format!("{}", i + NUM_PUBS + NUM_U256),
                    HASH_LEN as usize,
                )),
                WinternitzSecret::new(HASH_LEN as usize),
            );
        }

        commitment_map
    }
}
