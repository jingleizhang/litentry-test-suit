use std::{sync::mpsc::channel, time::SystemTime};

use litentry_test_suit::{
    identity_management::{api::IdentityManagementApi, events::IdentityManagementEventApi},
    primitives::{Identity, SubstrateNetwork},
    utils::{
        create_n_random_sr25519_address, generate_user_shielding_key, hex_account_to_address32,
    },
    ApiClient,
};
use sp_core::{sr25519, Pair};
use threadpool::ThreadPool;

/**
 * Including the corner case of everything
 *
 * Format:
 * 1. A detailed description of this corner case
 * 2. Implement this part of the verification code from scratch
 *
 */

/*
Description:
https://github.com/litentry/litentry-parachain/issues/1468

How long does it take to generate a VC with 20+ identities? What about 50 identities?
About 350 secs in this way
 */
#[test]
fn tc_request_vc_with_20s_identities_or_more_one_single_thread() {
    let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
    let api_client = ApiClient::new_with_signer(alice);

    let shard = api_client.get_shard();
    let user_shielding_key = generate_user_shielding_key();
    api_client.set_user_shielding_key(shard, user_shielding_key);

    let alice = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    let alice = hex_account_to_address32(alice).unwrap();
    let ciphertext_metadata: Option<Vec<u8>> = None;

    let networks = [
        SubstrateNetwork::Polkadot,
        SubstrateNetwork::Kusama,
        SubstrateNetwork::Litentry,
        SubstrateNetwork::Litmus,
        SubstrateNetwork::Khala,
    ];

    let identity_address = create_n_random_sr25519_address(6);
    let mut created_identity_idex = 0;

    let started_timestamp = SystemTime::now();
    networks.iter().for_each(|network| {
        identity_address.iter().for_each(|address| {
            let identity = Identity::Substrate {
                network: network.clone(),
                address: address.clone(),
            };
            api_client.create_identity(shard, alice, identity.clone(), ciphertext_metadata.clone());
            let event = api_client.wait_event_identity_created();
            assert!(event.is_ok());
            assert_eq!(event.unwrap().who, api_client.get_signer().unwrap());

            created_identity_idex += 1;
        })
    });

    let elapsed_secs = started_timestamp.elapsed().unwrap().as_secs();
    println!(
        " 🚩 created {} identities in one single thread using {} secs!",
        created_identity_idex, elapsed_secs
    );

    assert_eq!(created_identity_idex, 30);
}

#[test]
fn tc_request_vc_with_20s_identities_or_more_parallelise() {
    // FIXME: NOT DONE YET
    let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
    let api_client = ApiClient::new_with_signer(alice);

    let shard = api_client.get_shard();
    let user_shielding_key = generate_user_shielding_key();
    api_client.set_user_shielding_key(shard, user_shielding_key);

    let alice = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    let alice = hex_account_to_address32(alice).unwrap();
    let ciphertext_metadata: Option<Vec<u8>> = None;

    let networks = [
        SubstrateNetwork::Polkadot,
        SubstrateNetwork::Kusama,
        SubstrateNetwork::Litentry,
        SubstrateNetwork::Litmus,
        SubstrateNetwork::Khala,
    ];

    let identity_address = create_n_random_sr25519_address(6);
    let mut created_identity_idex = 0;

    let n_workers = 10;
    let n_jobs = 30;
    let pool = ThreadPool::new(n_workers);
    // Synchronized with a channel
    let (tx, rx) = channel();

    let nonce = api_client.clone().api.get_nonce().unwrap_or(0u32);

    let started_timestamp = SystemTime::now();
    networks.iter().for_each(|network| {
        identity_address.iter().for_each(|address| {
            let identity = Identity::Substrate {
                network: network.clone(),
                address: address.clone(),
            };

            let tx = tx.clone();
            let api_client = api_client.clone();
            let identity = identity.clone();
            let ciphertext_metadata = ciphertext_metadata.clone();

            pool.execute(move || {
                api_client.create_identity_offline(
                    nonce,
                    shard,
                    alice,
                    identity.clone(),
                    ciphertext_metadata.clone(),
                );

                let event = api_client.wait_event_identity_created();
                assert!(event.is_ok());

                let event = event.unwrap();
                assert_eq!(event.who, api_client.get_signer().unwrap());

                tx.send(event)
                    .expect("channel will be there waiting for the pool");
            });

            created_identity_idex += 1;
        })
    });

    let count = rx.iter().take(n_jobs).count();

    let elapsed_secs = started_timestamp.elapsed().unwrap().as_secs();
    println!(
        " 🚩 created {} identities in multi-thread using {} secs!",
        created_identity_idex, elapsed_secs
    );

    assert_eq!(created_identity_idex, count);
}

#[test]
fn tc_request_vc() {
    // let a4 = Assertion::A4(1_u128);
    // api_client.request_vc(shard, a4);

    // let event = api_client.wait_event_vc_issued();
    // assert!(event.is_ok());
}
