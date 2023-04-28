use codec::Encode;
use sp_core::{blake2_256, sr25519::Pair as SubstratePair, Pair};

use crate::primitives::{
    address::Address32,
    assertion::ParameterString,
    identity::{
        DiscordValidationData, Identity, IdentityMultiSignature, ValidationData, ValidationString,
        Web2ValidationData, Web3CommonValidationData, Web3ValidationData,
    },
    ChallengeCode,
};

use super::hex::hex_encode;

pub trait ValidationDataBuilder {
    fn build_vdata_substrate(
        pair: &SubstratePair,
        who: &Address32,
        identity: &Identity,
        code: &ChallengeCode,
    ) -> Result<ValidationData, Vec<u8>>;
}

impl ValidationDataBuilder for ValidationData {
    fn build_vdata_substrate(
        pair: &SubstratePair,
        who: &Address32,
        identity: &Identity,
        challenge_code: &ChallengeCode,
    ) -> Result<ValidationData, Vec<u8>> {
        let message = get_expected_raw_message(who, identity, challenge_code);
        let sr25519_sig = pair.sign(&message);
        let signature = IdentityMultiSignature::Sr25519(sr25519_sig);
        let message = ValidationString::try_from(message)?;

        let web3_common_validation_data = Web3CommonValidationData { message, signature };
        Ok(ValidationData::Web3(Web3ValidationData::Substrate(
            web3_common_validation_data,
        )))
    }
}

fn get_expected_raw_message(who: &Address32, identity: &Identity, code: &ChallengeCode) -> Vec<u8> {
    let mut payload = code.encode();
    payload.append(&mut who.encode());
    payload.append(&mut identity.encode());
    blake2_256(payload.as_slice()).to_vec()
}

pub fn build_vdata_discord() -> ValidationData {
    let v = DiscordValidationData {
        channel_id: ParameterString::try_from("919848392035794945".as_bytes().to_vec()).unwrap(),
        message_id: ParameterString::try_from("1101456458970824805".as_bytes().to_vec()).unwrap(),
        guild_id: ParameterString::try_from("919848390156767232".as_bytes().to_vec()).unwrap(),
    };

    let data = ValidationData::Web2(Web2ValidationData::Discord(v));
    data
}

pub fn build_msg_web2(
    who: &Address32,
    identity: &Identity,
    challenge_code: &ChallengeCode,
) -> String {
    let message = get_expected_raw_message(who, identity, challenge_code);
    let msg = hex_encode(message.as_slice());
    msg
}
