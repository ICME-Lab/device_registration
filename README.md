# DePIN Device Registration Using IoTeX ioConnect SDK and NovaNet ZKPs

This project demonstrates DePIN device registration using a secure client-server system built with Rust. It leverages IoTeX's ioConnect SDK for decentralized identity (DID) management and NovaNet's zkEngine for zero-knowledge proof generation.
The client collects GPS coordinates, timestamps, and signs them using cryptographic keys. The data is then transmitted with a zero-knowledge proof to the server for trustless verification.

## Overview

This system ensures:

- Data authenticity through ECDSA signatures managed with the ioConnect SDK.
- Privacy-preserving data integrity and computational correctness using zk-SNARKs from NovaNet’s zkEngine.
- Decentralized Identity Management for DePIN devices via DIDs and DID Documents (DIDDocs) using the ioConnect SDK.
- Secure transmission of GPS data and zero knowedge proofs over the network, with both client and server ensuring trust through cryptographic protocols.

# Prerequisites

Follow [this tutorial](https://github.com/simonerom/ioid-registration-js) to set-up the device and register it to a project on the IoTeX chain.

Also make sure the device is still listening to requests, as it will be asked to sign messages with it's DID key.

# How it works

## Client Side:

The client can then send a proof that it's located in a certain radius from a point (both defined in the circuit, i.e. by the service owning the server)

- The client collects GPS data.
- The client then generates a zk-SNARK proof of proximity.
- The client sends the proof to the device, so that it signs it with its DID key (TBD).
- The proof, together with the signature, is sent to the server.

## Server Side:

At the beginning of the service, the server creates the verifier key that will allow it to verify proofs sent by clients, stored in `vk.json`.

Then on receiving clients proofs, the server processes the following steps:

- It recovers the signers public address (i.e. device's public address).
- It verifies that the device is registered by requesting the ioid contract (TBD).
- It then verifies that the proof is valid and corresponds to a correct execution of the circuit.
- If verification succeeds, the server sends a success response. Otherwise, it returns an error.

# Project structure

- `/client` where all the client actions are developped, it is composed of:
  - `/src` where the different executables are located
- `/server` where the server is setup, composed of:
  - `/src` where the executable is located
    - `bin` where the executable to build the verifier key is located
    - `main.rs` where the executable to run the server is located

# Get started

## Starting the server

From `server` directory:

First build the verifier key corresponding to the circuit that we want to verify correct execution:

```
cargo +nightly run --bin build_vk
```

Once the verifier key has been built, we can run the server:

```
cargo +nightly run
```

The server will start listening on `127.0.0.1:3000`

## Running the client's functions

From `client` directory, on another terminal:

Once that is done, we can start sending position data to the server:

```
cargo +nighlty run

```
