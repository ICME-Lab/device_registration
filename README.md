# Onchain Verification and Rewards demo

This demo shows how an ioTex device creates a local zero-knowledge proof of its location, which is verified on the iotex chain and, if successfully verified, then the owner of the device receives a reward.

### Register a device and run it

This is necessary to sign the proof with the device's private key.

Follow https://github.com/iotexproject/ioID-SDK/tree/main/example/linux/deviceregister/doc

If on a Mac, you can run first a docker container with an open port on 8000:
```
docker run -it --rm --name ioid-sdk -p 8000:8000 -v $(pwd):/workspace  -w /workspace node:20 bash
```

Then run the exectutable `./DeviceRegister`.

Make sure to register your device on IoTeX testnet [here](https://hub.iotex.io/dev/pebble).

### Generate the solidity contract for the onchain verifier

```
cargo run generate-onchain-verifier-contract
```

This will generate the solidity contract and the calldata for the onchain verifier in `./hardhat/contracts/`.


#### Deploy the onchain verifier contract to IoTeX

```
cd hardhat
```

```
npx hardhat run scripts/deploy-onchain-verifier.js --network iotex_testnet
```

This will return the hash of the deployed contract.

### Deploy the rewards contract to IoTeX

1. Modify `./scripts/deploy-rewards-demo.js` and replace the `OnchainVerifier` address with the hash of the deployed contract.

```javascript
const contract = await RewardDistributor.deploy(
    "0xAD5f0101B94F581979AA22F123b7efd9501BfeB3", // OnchainVerifier contract
    "0x0A7e595C7889dF3652A19aF52C18377bF17e027D", // ioID Registry
    "0x45Ce3E6f526e597628c73B731a3e9Af7Fc32f5b7"  // ioID Contract
);
```

2. Deploy the rewards contract

```
npx hardhat run scripts/deploy-rewards-demo.js --network iotex_testnet
```

This will return the hash of the deployed contract.

#### Transfer IOTX to the rewards contract

This is necessary since it is the rewards contract that will pay the reward.

```
ioctl contract invoke bytecode 0x389daDF8A8A9C800B2d6212A28283f58FF1D43fB "" 2
```


### Run the demo and reward the owner of the device onchain

```
cd ..
```

1. Change the addresses of the deployed contracts in `./src/constants.rs`.

```rust
const NOVA_DECIDER_CONTRACT_ADDRESS = "0xAD5f0101B94F581979AA22F123b7efd9501BfeB3";
const REWARD_DISTRIBUTOR_CONTRACT_ADDRESS = "0xAD5f0101B94F581979AA22F123b7efd9501BfeB3";
```

2. Run the demo

```
cargo run
```

This will:
- generate a local proof of location
- compress the proof (locally but can be done with NovaNet)
- sign the compressed proof with the device's private key
- verify the proof onchain and reward the owner of the device
- print the transaction information of the rewards contract. You can check the transaction on IoTeX explorer.
https://testnet.iotexscan.io/



