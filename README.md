# DePIN Device Registration Using IoTeX ioConnect SDK and NovaNet ZKPs

This project demonstrates DePIN device registration using a secure client-server system built with Rust. It leverages IoTeX's ioID SDK for decentralized identity (DID) management and NovaNet's zkEngine for zero-knowledge proof generation.
The client collects GPS coordinates, and signs them using cryptographic keys. The data is then transmitted with a zero-knowledge proof to the server for trustless verification.

## Overview

This system ensures:

- Data authenticity through ECDSA signatures managed with the ioID SDK.
- Privacy-preserving data integrity and computational correctness using zk-SNARKs from NovaNet’s zkEngine.
- Decentralized Identity Management for DePIN devices via DIDs and DID Documents (DIDDocs) using the ioID SDK.

# Prerequisites

First install submodules:

```
git submodule init
git submodule update
```

We will simulate a device on our linux machine, and make it run the ioID SDK:

```
git clone https://github.com/iotexproject/ioID-SDK
```

Then allow the device to use ioID capabilities, by following [this tutorial](https://github.com/iotexproject/ioID-SDK/tree/main/example/linux/deviceregister/doc).
The device (our linux machine) should be listening at port `8000`

To create a project on the IoTeX chain, and allow a device to be registered to it, follow [this tutorial](https://docs.iotex.io/builders/depin/ioid-step-by-step-tutorial).

Once this is done, go to the ioID registration tool and install packages:

```
cd client/lib/ioid-registration-js
npm install
```

From there, follow the steps in the README except you don't have to go to the tutorial that is linked, as we already installed the ioID SDK.

We also need to set `.env` in `/server`:

```
IOTEX_TESTNET_RPC_URL=<your rpc url>
SPENDER_PRIVATE_KEY=<private key for the account that will send rewards - in hex format>
```

# How it works

## Client Side:

The client can then send a proof that it's located in a certain radius from a point (both defined in the circuit, i.e. by the service owning the server)

- The client collects GPS data.
- The client then generates a zk-SNARK proof of proximity.
- The client sends the proof to the device, so that it signs it with its DID key.
- The proof, together with the signature, is sent to the server.

## Server Side:

At the beginning of the service, the server creates the verifier key that will allow it to verify proofs sent by clients, stored in `vk.json`.

Then on receiving clients proofs, the server processes the following steps:

- It recovers the signers public address (i.e. device's public address).
- It verifies that the device is registered by requesting the ioid contract.
- It then verifies that the proof is valid and corresponds to a correct execution of the circuit.
- If verification succeeds, the server sends a success response. Otherwise, it returns an error.
- The server also retrieves the device owner's address to send a reward.

# Project structure

- `/client` where all the client actions are developped, it is composed of:
  - `/src` where the different executables are located
- `/server` where the server is setup, composed of:
  - `/src` where the executable is located
    - `bin` where the executable to build the verifier key is located
    - `main.rs` where the executable to run the server is located

# Get started

Make sure the device is still listening on `http://127.0.0.1:8000`

## Starting the server

From `server` directory:

First build the verifier key corresponding to the circuit that we want to verify correct execution:

```

cargo run --bin build_pp

```

Once the verifier key has been built, we can run the server:

```

cargo run

```

The server will start listening on `127.0.0.1:3000`

## Running the client's functions

From `client` directory, on another terminal:

Once that is done, we can start sending position data to the server:

```

cargo run

```

```

```
