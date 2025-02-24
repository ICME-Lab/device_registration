// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface INovaDecider {
    function verifyNovaProof(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof
    ) external view returns (bool);
}

interface IIoIDRegistry {
    function deviceTokenId(address deviceAddress) external view returns (uint256);
}

interface IIoID {
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract IoTeXRewardDistributor {
    address public owner;
    INovaDecider public novaDecider;
    IIoIDRegistry public ioIDRegistry;
    IIoID public ioID;

    event RewardSent(address indexed recipient, uint256 amount);
    event VerificationSuccess();
    event DeviceAddressRecovered(address deviceAddress);
    event DeviceOwnerFound(address ownerAddress);
    event DeviceIdFound(uint256 deviceId);

    constructor(
        address _novaDecider,
        address _ioIDRegistry,
        address _ioID
    ) {
        owner = msg.sender;
        novaDecider = INovaDecider(_novaDecider);
        ioIDRegistry = IIoIDRegistry(_ioIDRegistry);
        ioID = IIoID(_ioID);
    }

    function verifyAndReward(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof,
        bytes32 hash,    // The proof hash
        uint8 v, bytes32 r, bytes32 s // Signature components
    ) external payable {
        require(msg.value >= 1 ether, "Insufficient reward amount"); // Ensure contract has funds

        // Step 1: Call NovaDecider contract to verify proof
        bool validProof = novaDecider.verifyNovaProof(
            i_z0_zi, U_i_cmW_U_i_cmE, u_i_cmW, cmT_r, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof
        );
        require(validProof, "NovaDecider verification failed");
        emit VerificationSuccess();

        // Step 2: Recover device address from signature
        address deviceAddress = recoverSigner(hash, v, r, s);
        require(deviceAddress != address(0), "Invalid signature");
        emit DeviceAddressRecovered(deviceAddress);

        // Step 3: Get the device ID from ioIDRegistry
        uint256 deviceId = ioIDRegistry.deviceTokenId(deviceAddress);
        emit DeviceIdFound(deviceId);
        // Step 4: Get the device owner from ioID
        address ownerAddress = ioID.ownerOf(deviceId);
        require(ownerAddress != address(0), "Device owner not found");
        emit DeviceOwnerFound(ownerAddress);
        // Step 5: Send reward of 1 IOTX
        payable(ownerAddress).transfer(1 ether);

        emit RewardSent(ownerAddress, 1 ether);
    }

    function recoverSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(hash, v, r, s);
    }

    // Allows contract to receive deposits for rewards
    receive() external payable {}

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function verifyAndReward2(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof,
        bytes32 hash,    // The proof hash
        uint8 v, bytes32 r, bytes32 s // Signature components
    ) external payable returns (bool) {
        // require(msg.value >= 1 ether, "Insufficient reward amount"); // Ensure contract has funds

        // Step 1: Call NovaDecider contract to verify proof
        bool validProof = novaDecider.verifyNovaProof(
            i_z0_zi, U_i_cmW_U_i_cmE, u_i_cmW, cmT_r, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof
        );
        require(validProof, "NovaDecider verification failed");
        emit VerificationSuccess();

        // // Step 2: Recover device address from signature
        // address deviceAddress = recoverSigner(hash, v, r, s);
        // require(deviceAddress != address(0), "Invalid signature");
        // emit DeviceAddressRecovered(deviceAddress);

        // // Step 3: Get the device ID from ioIDRegistry
        // uint256 deviceId = ioIDRegistry.deviceTokenId(deviceAddress);
        // emit DeviceIdFound(deviceId);
        // // Step 4: Get the device owner from ioID
        // address ownerAddress = ioID.ownerOf(deviceId);
        // require(ownerAddress != address(0), "Device owner not found");
        // emit DeviceOwnerFound(ownerAddress);
        // // Step 5: Send reward of 1 IOTX
        // payable(ownerAddress).transfer(1 ether);

        // emit RewardSent(ownerAddress, 1 ether);
        return true;
    }


    function verifyAndReward3(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof,
        bytes32 hash,    // The proof hash
        uint8 v, bytes32 r, bytes32 s // Signature components
    ) external payable returns (bool) {
        require(msg.value >= 1 ether, "Insufficient reward amount"); // Ensure contract has funds

        // Step 1: Call NovaDecider contract to verify proof
        bool validProof = novaDecider.verifyNovaProof(
            i_z0_zi, U_i_cmW_U_i_cmE, u_i_cmW, cmT_r, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof
        );
        require(validProof, "NovaDecider verification failed");
        emit VerificationSuccess();

        // // Step 2: Recover device address from signature
        // address deviceAddress = recoverSigner(hash, v, r, s);
        // require(deviceAddress != address(0), "Invalid signature");
        // emit DeviceAddressRecovered(deviceAddress);

        // // Step 3: Get the device ID from ioIDRegistry
        // uint256 deviceId = ioIDRegistry.deviceTokenId(deviceAddress);
        // emit DeviceIdFound(deviceId);
        // // Step 4: Get the device owner from ioID
        // address ownerAddress = ioID.ownerOf(deviceId);
        // require(ownerAddress != address(0), "Device owner not found");
        // emit DeviceOwnerFound(ownerAddress);
        // // Step 5: Send reward of 1 IOTX
        // payable(ownerAddress).transfer(1 ether);

        // emit RewardSent(ownerAddress, 1 ether);
        return true;
    }


    function verifyAndReward4(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof,
        bytes32 hash,    // The proof hash
        uint8 v, bytes32 r, bytes32 s // Signature components
    ) external payable returns (address) {
        require(msg.value >= 1 ether, "Insufficient reward amount"); // Ensure contract has funds

        // Step 1: Call NovaDecider contract to verify proof
        bool validProof = novaDecider.verifyNovaProof(
            i_z0_zi, U_i_cmW_U_i_cmE, u_i_cmW, cmT_r, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof
        );
        require(validProof, "NovaDecider verification failed");
        emit VerificationSuccess();

        // Step 2: Recover device address from signature
        address deviceAddress = recoverSigner(hash, v, r, s);
        require(deviceAddress != address(0), "Invalid signature");
        emit DeviceAddressRecovered(deviceAddress);

        // // Step 3: Get the device ID from ioIDRegistry
        // uint256 deviceId = ioIDRegistry.deviceTokenId(deviceAddress);
        // emit DeviceIdFound(deviceId);
        // // Step 4: Get the device owner from ioID
        // address ownerAddress = ioID.ownerOf(deviceId);
        // require(ownerAddress != address(0), "Device owner not found");
        // emit DeviceOwnerFound(ownerAddress);
        // // Step 5: Send reward of 1 IOTX
        // payable(ownerAddress).transfer(1 ether);

        // emit RewardSent(ownerAddress, 1 ether);
        return deviceAddress;
    }


    function verifyAndReward5(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof,
        bytes32 hash,    // The proof hash
        uint8 v, bytes32 r, bytes32 s // Signature components
    ) external payable returns (uint256) {
        require(msg.value >= 1 ether, "Insufficient reward amount"); // Ensure contract has funds

        // Step 1: Call NovaDecider contract to verify proof
        bool validProof = novaDecider.verifyNovaProof(
            i_z0_zi, U_i_cmW_U_i_cmE, u_i_cmW, cmT_r, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof
        );
        require(validProof, "NovaDecider verification failed");
        emit VerificationSuccess();

        // Step 2: Recover device address from signature
        address deviceAddress = recoverSigner(hash, v, r, s);
        require(deviceAddress != address(0), "Invalid signature");
        emit DeviceAddressRecovered(deviceAddress);

        // Step 3: Get the device ID from ioIDRegistry
        uint256 deviceId = ioIDRegistry.deviceTokenId(deviceAddress);
        emit DeviceIdFound(deviceId);
        // // Step 4: Get the device owner from ioID
        // address ownerAddress = ioID.ownerOf(deviceId);
        // require(ownerAddress != address(0), "Device owner not found");
        // emit DeviceOwnerFound(ownerAddress);
        // // Step 5: Send reward of 1 IOTX
        // payable(ownerAddress).transfer(1 ether);

        // emit RewardSent(ownerAddress, 1 ether);
        return deviceId;
    }

      function verifyAndReward6(
        uint256[3] calldata i_z0_zi, 
        uint256[4] calldata U_i_cmW_U_i_cmE, 
        uint256[2] calldata u_i_cmW, 
        uint256[3] calldata cmT_r, 
        uint256[2] calldata pA, 
        uint256[2][2] calldata pB, 
        uint256[2] calldata pC, 
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, 
        uint256[2][2] calldata kzg_proof,
        bytes32 hash,    // The proof hash
        uint8 v, bytes32 r, bytes32 s // Signature components
    ) external payable returns (address) {
        require(msg.value >= 1 ether, "Insufficient reward amount"); // Ensure contract has funds

        // Step 1: Call NovaDecider contract to verify proof
        bool validProof = novaDecider.verifyNovaProof(
            i_z0_zi, U_i_cmW_U_i_cmE, u_i_cmW, cmT_r, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof
        );
        require(validProof, "NovaDecider verification failed");
        emit VerificationSuccess();

        // Step 2: Recover device address from signature
        address deviceAddress = recoverSigner(hash, v, r, s);
        require(deviceAddress != address(0), "Invalid signature");
        emit DeviceAddressRecovered(deviceAddress);

        // Step 3: Get the device ID from ioIDRegistry
        uint256 deviceId = ioIDRegistry.deviceTokenId(deviceAddress);
        emit DeviceIdFound(deviceId);
        // Step 4: Get the device owner from ioID
        address ownerAddress = ioID.ownerOf(deviceId);
        require(ownerAddress != address(0), "Device owner not found");
        emit DeviceOwnerFound(ownerAddress);
        // Step 5: Send reward of 1 IOTX
        payable(ownerAddress).transfer(1 ether);

        emit RewardSent(ownerAddress, 1 ether);
        return ownerAddress;
    }
}
