pub mod identity_management;
pub mod primitives;
pub mod utils;
pub mod vc_management;

#[macro_use]
extern crate lazy_static;

use crate::primitives::{Enclave, MrEnclave};
use aes_gcm::{aead::OsRng, Aes256Gcm, KeyInit};
use primitives::RsaPublicKeyGenerator;
use rsa::RsaPublicKey;
use sp_core::{crypto::AccountId32 as AccountId, hexdisplay::HexDisplay, Pair};
use sp_runtime::{MultiSignature, MultiSigner};
use substrate_api_client::{rpc::WsRpcClient, Api, Metadata, PlainTipExtrinsicParams, XtStatus};

lazy_static! {
    pub static ref USER_AES256G_KEY: Vec<u8> = {
        let aes_key = Aes256Gcm::generate_key(&mut OsRng);
        aes_key.to_vec()
    };
}

const NODE_URL: &str = "ws://127.0.0.1:9944";
pub type ApiType<P> = Api<P, WsRpcClient, PlainTipExtrinsicParams>;

#[derive(Clone)]
pub struct ApiClient<P>
where
    P: Pair,
{
    pub api: ApiType<P>,
}

impl<P> ApiClient<P>
where
    P: Pair,
    MultiSignature: From<P::Signature>,
    MultiSigner: From<P::Public>,
{
    pub fn new_with_signer(signer: P) -> Self {
        let client = WsRpcClient::new(NODE_URL);
        let api = ApiType::new(client)
            .map(|api| api.set_signer(signer))
            .unwrap();

        ApiClient { api }
    }

    pub fn get_signer(&self) -> Option<AccountId> {
        self.api.signer_account()
    }

    pub fn send_extrinsic(&self, xthex_prefixed: String) {
        let tx_hash = self
            .api
            .send_extrinsic(xthex_prefixed, XtStatus::InBlock)
            .unwrap();
        println!(" ✅ Transaction got included. Hash: {:?}", tx_hash);
    }

    pub fn get_tee_shielding_pubkey(&self) -> RsaPublicKey {
        let enclave_count: u64 = self
            .api
            .get_storage_value("Teerex", "EnclaveCount", None)
            .unwrap()
            .unwrap();

        let enclave: Enclave<AccountId, Vec<u8>> = self
            .api
            .get_storage_map("Teerex", "EnclaveRegistry", enclave_count, None)
            .unwrap()
            .unwrap();

        let shielding_key = enclave.shielding_key.unwrap();
        RsaPublicKey::new_with_rsa3072_pubkey(shielding_key)
    }

    pub fn get_shard(&self) -> MrEnclave {
        let enclave_count: u64 = self
            .api
            .get_storage_value("Teerex", "EnclaveCount", None)
            .unwrap()
            .unwrap();

        let enclave: Enclave<AccountId, Vec<u8>> = self
            .api
            .get_storage_map("Teerex", "EnclaveRegistry", enclave_count, None)
            .unwrap()
            .unwrap();

        let shard = enclave.mr_enclave;
        let shard_in_hex = format!("0x{}", HexDisplay::from(&shard));

        println!("\n ✅ Hex shard : {}", shard_in_hex);

        shard
    }
}

/// FIXME: Maybe use this later...
pub trait ParachainMetadataApi {
    fn metadata(&self);
    fn get_total_issuance(&self);
}

impl<P> ParachainMetadataApi for ApiClient<P>
where
    P: Pair,
    MultiSignature: From<P::Signature>,
    MultiSigner: From<P::Public>,
{
    fn metadata(&self) {
        let meta = Metadata::try_from(self.api.get_metadata().unwrap()).unwrap();
        meta.print_overview();
    }

    fn get_total_issuance(&self) {
        let result: u128 = self
            .api
            .get_storage_value("Balances", "TotalIssuance", None)
            .unwrap()
            .unwrap();
        println!("[+] TotalIssuance is {}", result);
    }
}

pub trait MockApiClient {
    fn mock_get_shard(&self) -> MrEnclave;
}

impl<P> MockApiClient for ApiClient<P>
where
    P: Pair,
    MultiSignature: From<P::Signature>,
    MultiSigner: From<P::Public>,
{
    fn mock_get_shard(&self) -> MrEnclave {
        [
            65_u8, 56, 208, 116, 135, 54, 101, 208, 13, 173, 159, 82, 115, 60, 181, 148, 205, 211,
            71, 48, 174, 210, 172, 218, 70, 146, 182, 230, 5, 74, 110, 208,
        ]
    }
}
