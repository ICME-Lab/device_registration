#![allow(non_snake_case)]

use std::str::FromStr;

use anyhow::Result;
use constants::{NOVANET_ACCOUNT_ADDRESS, RPC_URL};
use contracts::print_reward_contract_balance;
use proof::setup_decider;
use rand::thread_rng;

use radius_circuit::circuit::ProximityCircuit;

use nova::{onchain::utils::get_formatted_calldata, provider::Bn256EngineKZG, traits::Engine};

use test::run_test_onchain_reward;
use web3::Web3;
use web3::{
    contract::{Contract, Error, Options},
    transports::Http,
    types::{H160, H256, U256},
};

use crate::{
    calldata::{generate_iotex_reward_calldata, generate_iotex_verifier_calldata},
    contracts::{get_nova_decider_contract, get_reward_distributor_contract},
    proof::{generate_decider_proof, generate_rs_proof, sign_proof_with_device, verify_proof},
    solidity::generate_solidity_verifier,
};

pub mod calldata;
pub mod constants;
pub mod contracts;
pub mod proof;
pub mod solidity;
pub mod test;
pub mod utils;

pub async fn run_onchain_verification(
    nova_decider_contract: Contract<Http>,
    verifier_calldata: (
        [U256; 3],
        [U256; 4],
        [U256; 2],
        [U256; 3],
        [U256; 2],
        [[U256; 2]; 2],
        [U256; 2],
        [U256; 4],
        [[U256; 2]; 2],
    ),
) -> Result<bool, Error> {
    nova_decider_contract
        .query(
            "verifyNovaProof",
            verifier_calldata,
            None,
            Options::default(),
            None,
        )
        .await
}

pub async fn run_onchain_reward(
    reward_distributor_contract: Contract<Http>,
    reward_calldata: (
        [U256; 3],
        [U256; 4],
        [U256; 2],
        [U256; 3],
        [U256; 2],
        [[U256; 2]; 2],
        [U256; 2],
        [U256; 4],
        [[U256; 2]; 2],
        H256,
        u8,
        H256,
        H256,
    ),
) -> Result<H256> {
    let options = Options {
        value: None,
        // value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
        gas: Some(U256::from_dec_str("500000").unwrap()), // Optional, increase if needed
        ..Default::default()
    };

    let secp_secret_key = web3::signing::SecretKey::from_str(
        "5f840d5809d857ee3be4e970fc51f51800436763fd43a114649ce87a65ec5e41",
    )
    .expect("Invalid private key");

    let transport = Http::new(RPC_URL)?; // Replace with your Ethereum node URL
    let web3 = Web3::new(transport);

    // let res_tx_hash: Result<H256, Error> = reward_distributor_contract
    //     .call(
    //         "verifyAndReward",
    //         reward_calldata,
    //         H160::from_str(NOVANET_ACCOUNT_ADDRESS).unwrap(),
    //         options,
    //         // &secp_secret_key,
    //     )
    //     .await;

    let res_tx_hash: Result<H256, Error> = reward_distributor_contract
        .signed_call(
            "verifyAndReward",
            reward_calldata,
            options,
            &secp_secret_key,
        )
        .await
        .map_err(|e| Error::from(e));

    // Wait for 5 seconds
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    match res_tx_hash {
        Ok(tx_hash) => {
            println!("Transaction sent, hash: {:?}", tx_hash);
            // Fetch transaction receipt
            match web3.eth().transaction_receipt(tx_hash).await? {
                Some(receipt) => {
                    let pretty_receipt = serde_json::to_string_pretty(&receipt)
                        .unwrap_or_else(|_| "Failed to serialize receipt".to_string());
                    println!("Transaction Receipt: {}", pretty_receipt);
                }
                None => {
                    println!("Transaction is still pending.");
                }
            }
            Ok(tx_hash)
        }
        Err(e) => {
            println!("Error sending transaction: {:?}", e);
            Err(anyhow::anyhow!("Error sending transaction: {:?}", e))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let latitude = 4990;
    let longitude = 5010;

    // create signing circuit
    // checks that the input is in a radius of 100 from the point at (5000, 5000), hardcoded in the circuit definition
    let circuit = ProximityCircuit::new(
        <<Bn256EngineKZG as Engine>::Scalar>::from(latitude as u64),
        <<Bn256EngineKZG as Engine>::Scalar>::from(longitude as u64),
    );

    let (rs, rs_pp) = generate_rs_proof(circuit);
    let mut rng = thread_rng();
    let decider_vk = setup_decider(rs_pp.clone(), &mut rng);
    let compressed_snark = generate_decider_proof(rs, rs_pp, &mut rng);
    let (hash, signature) = sign_proof_with_device(&compressed_snark);
    assert!(verify_proof(&compressed_snark, &decider_vk));
    let calldata = generate_solidity_verifier(&compressed_snark, &decider_vk);
    let formatted_calldata = get_formatted_calldata(calldata.clone());
    let verifier_calldata = generate_iotex_verifier_calldata(&formatted_calldata);
    let reward_calldata = generate_iotex_reward_calldata(&formatted_calldata, signature, hash);
    let reward_distributor_contract = get_reward_distributor_contract()?;
    let nova_decider_contract = get_nova_decider_contract()?;
    print_reward_contract_balance(&reward_distributor_contract).await;
    let onchain_verification =
        run_onchain_verification(nova_decider_contract, verifier_calldata).await?;
    assert!(onchain_verification);
    run_test_onchain_reward(reward_distributor_contract.clone(), reward_calldata).await;
    let onchain_reward = run_onchain_reward(reward_distributor_contract, reward_calldata).await?;
    println!("Transaction hash: {:?}", onchain_reward);
    Ok(())
}
