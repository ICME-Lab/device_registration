# DePIN Device Registration IoTeX ioConnect SDK and NovaNet zkEngine

This project demonstrates DePIN device registration using a secure client-server system built with Rust, It leverages IoTeX's ioConnect SDK for decentralized identity (DID) management and NovaNet's zkEngine for zero-knowledge proof generation.
The client collects GPS coordinates, timestamps, and signs them using cryptographic keys. The data is then transmitted with a zero-knowledge proof to the server for trustless verification.

## Overview

This system ensures:

- Data authenticity through ECDSA signatures managed with the ioConnect SDK.
- Privacy-preserving data integrity and computational correctness using zk-SNARKs from NovaNet’s zkEngine.
- Decentralized Identity Management for DePIN devices via DIDs and DID Documents (DIDDocs) using the ioConnect SDK.
- Secure transmission of GPS data and zero knowedge proofs over the network, with both client and server ensuring trust through cryptographic protocols.

# How it works

## Client Side:

First, the client generates a DIDDoc using it's secret key, and sends it to the server to registrate.

The client can then send its position with a timestamp with the following workflow:

- The client collects GPS data and timestamps it.
- It signs the data in a ZK circuit, using the secret key associated to the DIDDoc.
- The client then generates a zk-SNARK proof of the signed data using NovaNet’s zkEngine.
- The proof, together with the position object and device DID is then sent to the server.

## Server Side:

The server first uses the ioConnect SDK to process the received DIDDoc to register the client

Then on receiving clients position, the server processes the following steps:

- It verifies the sender is registered to the service by checking the device DID, and recovers the associated public key.
- It then verifies that the proof is valid and corresponds to a correct execution of the circuit.
- The signature is then retrieved from the proof, and verified using the public key.
- If verification succeeds, the server sends a success response. Otherwise, it returns an error.

# Project structure

- `/client` where all the client actions are developped, it is composed of:
  - `/device_register` which handles the interactions with ioConnect SDK to create the DIDDoc.
  - `/src` where the different executables are located
- `/server` where the server is setup, composed of:
  - `/src` where the executable is located
  - `/did_mapping` where the registered devices are stored

# Get started

## Setting up client

Navigate to the `/client` directory:

```
cd client
```

Create a `.env` file to store the private key, as a 64-characters hexadecimal string, corresponding to a 32-bytes secret key.

```
# .env
SECRET_KEY_HEX=<your secret key in hex>
```

1. Device register

Copy the `core` directory from `device_register/ioConnect` to `device_register/src`.

in `device_register/src/core/src/include/config`, remove `autoconfig.h` and rename `autoconfig_linux.h` to `autoconfig.h`

Then build the executable that will generate the DID and DIDDoc used to registed the device:

```
cd device_register/src && \
mkdir build && cd build && \
cmake .. && make && ./DIDComm_server
```

Running `./DIDComm_Server` creates a DIDDoc using our secret key and stores it in a file (`peerDIDDoc.json` at `client/device_register`) for later use.

## Setting up server

From project root, get to the `add_client` directory:

```
cd server/add_client
```

Create a `libraries` directory, and in there also copy `core` directory from `ioConnect`, and change the `autoconfig.h` following same logic as in `Setting up client`.

then:

```
mkdir build && cd build && \
cmake .. && make
```

This will create a `./add_client` executable which will be used later by the server to register devices.

Now that the setup is done, we will walk through running the example

# Using demo

## Starting the server

From `server` directory:

First build the public params corresponding to the circuit that we want to verify correct execution:

```
cargo +nightly run --bin build_pp
```

Once the public params have been built, we can run the server:

```
cargo +nightly run
```

The server will start listening on `127.0.0.1:3000`

## Running the client's functions

From `client` directory, on another terminal:

First we need to register the device to the server:

```
cargo +nightly run --bin register_device
```

Once that is done, we can start sending position data to the server:

```
cargo +nighlty run
```
