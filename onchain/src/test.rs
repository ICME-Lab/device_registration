use web3::{
    contract::{Contract, Options},
    transports::Http,
    types::{H160, H256, U256},
};

pub async fn run_test_onchain_reward(
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
) {
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
        Ok(verified) => {
            println!("Groth16 proof verified: {:?}", verified);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let options = Options {
        value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
        ..Default::default()
    };
    let res_tx_hash: Result<H160, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward4",
            reward_calldata,
            None,
            options.clone(),
            None,
        )
        .await;
    match res_tx_hash {
        Ok(device_address) => {
            println!("Device address: {:?}", device_address);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let res_tx_hash: Result<U256, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward5",
            reward_calldata,
            None,
            options.clone(),
            None,
        )
        .await;
    match res_tx_hash {
        Ok(device_id) => {
            println!("Device ID: {:?}", device_id);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let res_tx_hash: Result<H160, web3::contract::Error> = reward_distributor_contract
        .query(
            "verifyAndReward6",
            reward_calldata,
            None,
            options.clone(),
            None,
        )
        .await;
    match res_tx_hash {
        Ok(owner_address) => {
            println!("Owner address: {:?}", owner_address);
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }
}
