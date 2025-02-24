#![allow(non_snake_case)]

use std::{str::FromStr, time::Instant};

use anyhow::Result;
use contracts::print_reward_contract_balance;
use halo2curves::bn256::{Bn256, Fr};
use proof::setup_decider;
use rand::{rngs::ThreadRng, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};

use ff::Field;
use radius_circuit::circuit::ProximityCircuit;
use sha2::{self, Digest};

use nova::{
    nebula::rs::{PublicParams, RecursiveSNARK},
    onchain::{
        decider::{prepare_calldata, Decider, DeciderProverKey, DeciderVerifierKey},
        eth::evm::{compile_solidity, Evm},
        utils::{get_formatted_calldata, get_function_selector_for_nova_cyclefold_verifier},
        verifiers::{
            groth16::SolidityGroth16VerifierKey,
            kzg::SolidityKZGVerifierKey,
            nebula::{get_decider_template_for_cyclefold_decider, NovaCycleFoldVerifierKey},
        },
    },
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};

use bson::{from_slice, to_vec};
use secp256k1::SecretKey as SecpSecretKey;
use std::fs::File;
use std::io::{Read, Write};
use utils::sign;
use web3::{
    contract::{deploy::Error, tokens::Tokenize, Contract, Options},
    signing::SecretKey,
    transports::Http,
    types::{Address, Recovery, RecoveryMessage, TransactionParameters, H160, H256, U128, U256},
};

use crate::{proof::{generate_rs_proof, generate_decider_proof, sign_proof_with_device, verify_proof}, calldata::{generate_iotex_verifier_calldata, generate_iotex_reward_calldata}, contracts::{get_reward_distributor_contract, get_nova_decider_contract}, solidity::generate_solidity_verifier};

pub mod utils;
pub mod calldata;
pub mod solidity;
pub mod proof;
pub mod contracts;
pub mod constants;


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

    let options = Options {
        value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
        // gas: Some(U256::from(500000)), // 500,000 gas (reasonable default)
        gas: Some(U256::from_dec_str("500000").unwrap()), // Optional, increase if needed
        // gas_price: Some(U256::from(1000000000)), // 1 Gwei
        ..Default::default()
    };

    let res_tx_hash: Result<bool, web3::contract::Error> = nova_decider_contract
        .query(
            "verifyNovaProof",
            verifier_calldata,
            None,
            Options::default(),
            None,
        )
        .await;
    match res_tx_hash {
        Ok(tx_hash) => println!("Transaction sent, hash: {:?}", tx_hash),
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let res_tx_hash: Result<bool, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward2",
            reward_calldata,
            None,
            Options::default(),
            None,
        )
        .await;
    match res_tx_hash {
        Ok(tx_hash) => {
            println!("Transaction sent, hash: {:?}", tx_hash);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let res_tx_hash: Result<H160, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward4",
            reward_calldata,
            None,
            Options {
                value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
                ..Default::default()
            },
            None,
        )
        .await;
    match res_tx_hash {
        Ok(tx_hash) => {
            println!("Transaction sent, hash: {:?}", tx_hash);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let res_tx_hash: Result<U256, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward5",
            reward_calldata,
            None,
            Options {
                value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
                ..Default::default()
            },
            None,
        )
        .await;
    match res_tx_hash {
        Ok(tx_hash) => {
            println!("Transaction sent, hash: {:?}", tx_hash);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let res_tx_hash: Result<H160, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward6",
            reward_calldata,
            None,
            Options {
                value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
                ..Default::default()
            },
            None,
        )
        .await;
    match res_tx_hash {
        Ok(tx_hash) => {
            println!("Transaction sent, hash: {:?}", tx_hash);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    // let secp_secret_key = web3::signing::SecretKey::from_str(
    //     "ee19147e85b07e448be482f7e7f946c6ac8692ba942891b9b6120d7d2aee1a98",
    // )
    // .expect("Invalid private key");

    // let res_tx_hash: Result<H256, web3::Error> = reward_distributor_contract
    //     .signed_call(
    //         "verifyAndReward",
    //         (
    //             i_z0_zi,
    //             U_i_cmW_U_i_cmE,
    //             u_i_cmW,
    //             cmT_r,
    //             pA,
    //             pB,
    //             pC,
    //             challenge_W_challenge_E_kzg_evals,
    //             kzg_proof,
    //             hash_h256,
    //             signature_v,
    //             signature_r,
    //             signature_s,
    //         ),
    //         options.clone(),
    //         &secp_secret_key,
    //     )
    //     .await;
    // match res_tx_hash {
    //     Ok(tx_hash) => {
    //         println!("Transaction sent, hash: {:?}", tx_hash);
    //         // Fetch transaction receipt
    //         match web3.eth().transaction_receipt(tx_hash).await? {
    //             Some(receipt) => {
    //                 println!("Transaction Receipt: {:?}", receipt);
    //                 if let Some(status) = receipt.status {
    //                     if status == 1.into() {
    //                         println!("✅ Transaction Successful!");
    //                     } else {
    //                         println!("❌ Transaction Failed!");
    //                         for log in receipt.logs {
    //                             println!("Log: {:?}", log);
    //                         }
    //                     }
    //                 }
    //             }
    //             None => println!("Transaction is still pending."),
    //         }
    //     }
    //     Err(e) => println!("Error sending transaction: {:?}", e),
    // }

    // println!("device_id: {:?}", device_id);
    // let ioid_contract = Contract::from_json(
    //     web3.eth(),
    //     H160::from_str(IOID_CONTRACT_ADDRESS).unwrap(),
    //     include_bytes!("../contract-abi/ioID-ABI.json"),
    // )
    // .unwrap();

    // println!("ioid_contract: {:?}", ioid_contract);

    // let owner_address: Address = ioid_contract
    //     .query("ownerOf", device_id, None, Options::default(), None)
    //     .await
    //     .unwrap();
    // println!("Proof verified. Sending reward to {:?}", owner_address);

    // /*
    //  * Send reward to device's owner
    //  */
    // let tx_object = TransactionParameters {
    //     to: Some(owner_address),
    //     value: U256::exp10(1),
    //     ..Default::default()
    // };

    // let spender_sk =
    //     SecretKey::from_str("ee19147e85b07e448be482f7e7f946c6ac8692ba942891b9b6120d7d2aee1a98")
    //         .unwrap();
    // let signed_tx = web3
    //     .accounts()
    //     .sign_transaction(tx_object, &spender_sk)
    //     .await
    //     .unwrap();

    // let result = web3
    //     .eth()
    //     .send_raw_transaction(signed_tx.raw_transaction)
    //     .await
    //     .unwrap_or_else(|e| {
    //         panic!("Failed to send transaction: {:?}", e);
    //     });

    // println!("Proof verified. Transaction hash: {:?}", result);
    /*
     * SEND TO SERVER FOR VERIFICATION
     * The server will verify the proof, recover the signer's public key using the signature
     *
     * TODO: then request the ioID contract to recover the device's owner, to send him the reward
     */

    // let body = SendDataBody {
    //     snark: compressed_snark,
    //     signature: signature,
    // };

    // println!("Sending proof and signature to server...");
    // let client = reqwest::Client::new();
    // let url = "http://127.0.0.1:3000/send_data";
    // let response = client
    //     .post(url)
    //     .header("Content-Type", "application/json")
    //     .body(serde_json::to_string(&body).expect("JSON serialization"))
    //     .send()
    //     .await?;

    // let result: SendDataResult = response.json().await?;
    // println!("Result: {}", result.message);
    Ok(())
}
