// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

/*
    Sonobe's Nova + CycleFold decider verifier.
    Joint effort by 0xPARC & PSE.

    More details at https://github.com/privacy-scaling-explorations/sonobe
    Usage and design documentation at https://privacy-scaling-explorations.github.io/sonobe-docs/

    Uses the https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs
    Groth16 verifier implementation and a KZG10 Solidity template adapted from
    https://github.com/weijiekoh/libkzg.
    Additionally we implement the NovaDecider contract, which combines the
    Groth16 and KZG10 verifiers to verify the zkSNARK proofs coming from
    Nova+CycleFold folding.
*/


/* =============================== */
/* KZG10 verifier methods */
/**
 * @author  Privacy and Scaling Explorations team - pse.dev
 * @dev     Contains utility functions for ops in BN254; in G_1 mostly.
 * @notice  Forked from https://github.com/weijiekoh/libkzg.
 * Among others, a few of the changes we did on this fork were:
 * - Templating the pragma version
 * - Removing type wrappers and use uints instead
 * - Performing changes on arg types
 * - Update some of the `require` statements 
 * - Use the bn254 scalar field instead of checking for overflow on the babyjub prime
 * - In batch checking, we compute auxiliary polynomials and their commitments at the same time.
 */
contract KZG10Verifier {

    // prime of field F_p over which y^2 = x^3 + 3 is defined
    uint256 public constant BN254_PRIME_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /**
     * @notice  Performs scalar multiplication in G_1.
     * @param   p  G_1 point to multiply
     * @param   s  Scalar to multiply by
     * @return  r  G_1 point p multiplied by scalar s
     */
    function mulScalar(uint256[2] memory p, uint256 s) internal view returns (uint256[2] memory r) {
        uint256[3] memory input;
        input[0] = p[0];
        input[1] = p[1];
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success
            case 0 { invalid() }
        }
        require(success, "bn254: scalar mul failed");
    }

    /**
     * @notice  Negates a point in G_1.
     * @param   p  G_1 point to negate
     * @return  uint256[2]  G_1 point -p
     */
    function negate(uint256[2] memory p) internal pure returns (uint256[2] memory) {
        if (p[0] == 0 && p[1] == 0) {
            return p;
        }
        return [p[0], BN254_PRIME_FIELD - (p[1] % BN254_PRIME_FIELD)];
    }

    /**
     * @notice  Adds two points in G_1.
     * @param   p1  G_1 point 1
     * @param   p2  G_1 point 2
     * @return  r  G_1 point p1 + p2
     */
    function add(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory r) {
        bool success;
        uint256[4] memory input = [p1[0], p1[1], p2[0], p2[1]];
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: point add failed");
    }

    /**
     * @notice  Computes the pairing check e(p1, p2) * e(p3, p4) == 1
     * @dev     Note that G_2 points a*i + b are encoded as two elements of F_p, (a, b)
     * @param   a_1  G_1 point 1
     * @param   a_2  G_2 point 1
     * @param   b_1  G_1 point 2
     * @param   b_2  G_2 point 2
     * @return  result  true if pairing check is successful
     */
    function pairing(uint256[2] memory a_1, uint256[2][2] memory a_2, uint256[2] memory b_1, uint256[2][2] memory b_2)
        internal
        view
        returns (bool result)
    {
        uint256[12] memory input = [
            a_1[0],
            a_1[1],
            a_2[0][1], // imaginary part first
            a_2[0][0],
            a_2[1][1], // imaginary part first
            a_2[1][0],
            b_1[0],
            b_1[1],
            b_2[0][1], // imaginary part first
            b_2[0][0],
            b_2[1][1], // imaginary part first
            b_2[1][0]
        ];

        uint256[1] memory out;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x180, out, 0x20)
            switch success
            case 0 { invalid() }
        }

        require(success, "bn254: pairing failed");

        return out[0] == 1;
    }

    uint256[2] G_1 = [
            0x171149d656ab2678f03a81fb4a13b38cb13c584222498b9f0824377ff4ef1c6c,
            0x1078a9c7358344c97989a825cd493c02502c5979785ab4102b85cab8785e1652
    ];
    uint256[2][2] G_2 = [
        [
            0x2e85a64b176a89f651b755522402780ac5224a690c62c2a3580e2b77391eb85f,
            0x25a630e1b1bb847ca0e32e8d5a2c62d424e4b0d67d8295d094589efba2611485
        ],
        [
            0x105e2254f385a54471f0f072b96fc88fc2a55e98e8fccbdcd5da2729f42941c7,
            0x1478cea7a3717eed37243042378ca4d61c6d69d433ecbf2967d813cb1adc02ae
        ]
    ];
    uint256[2][2] VK = [
        [
            0x213df544b48e424ce1eca450ed03a5496169eddd748b653832354ca0bcf23f62,
            0x2959a960103c0295e1a16715e806239ff6c59e4c0743824c117de81ae7f85c96
        ],
        [
            0x2dc616d796b0ecac95c855ccb68ea147ba7ae912cc510afd22db4596056d6886,
            0x1afc010c12a7d030252d49bbe091ac357b40f62e2c1ac4c1f346b20ce3c2c5c6
        ]
    ];

    

    /**
     * @notice  Verifies a single point evaluation proof. Function name follows `ark-poly`.
     * @dev     To avoid ops in G_2, we slightly tweak how the verification is done.
     * @param   c  G_1 point commitment to polynomial.
     * @param   pi G_1 point proof.
     * @param   x  Value to prove evaluation of polynomial at.
     * @param   y  Evaluation poly(x).
     * @return  result Indicates if KZG proof is correct.
     */
    function check(uint256[2] calldata c, uint256[2] calldata pi, uint256 x, uint256 y)
        public
        view
        returns (bool result)
    {
        //
        // we want to:
        //      1. avoid gas intensive ops in G2
        //      2. format the pairing check in line with what the evm opcode expects.
        //
        // we can do this by tweaking the KZG check to be:
        //
        //          e(pi, vk - x * g2) = e(c - y * g1, g2) [initial check]
        //          e(pi, vk - x * g2) * e(c - y * g1, g2)^{-1} = 1
        //          e(pi, vk - x * g2) * e(-c + y * g1, g2) = 1 [bilinearity of pairing for all subsequent steps]
        //          e(pi, vk) * e(pi, -x * g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(-x * pi, g2) * e(-c + y * g1, g2) = 1
        //          e(pi, vk) * e(x * -pi - c + y * g1, g2) = 1 [done]
        //                        |_   rhs_pairing  _|
        //
        uint256[2] memory rhs_pairing =
            add(mulScalar(negate(pi), x), add(negate(c), mulScalar(G_1, y)));
        return pairing(pi, VK, rhs_pairing, G_2);
    }

    function evalPolyAt(uint256[] memory _coefficients, uint256 _index) public pure returns (uint256) {
        uint256 m = BN254_SCALAR_FIELD;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }

    
}

/* =============================== */
/* Groth16 verifier methods */
/*
    Copyright 2021 0KIMS association.

    * `solidity-verifiers` added comment
        This file is a template built out of [snarkJS](https://github.com/iden3/snarkjs) groth16 verifier.
        See the original ejs template [here](https://github.com/iden3/snarkjs/blob/master/templates/verifier_groth16.sol.ejs)
    *

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 0x25b3c1df2b3ee1b0a8e65c8e54729b6cbb1e3f2b807fee4ffe4116b9c09029cd;
    uint256 constant alphay  = 0x2c44e29caa7f7a8c9656b464e04b039c7b453e5afb830ee192c44946a6d4080b;
    uint256 constant betax1  = 0x18a0a693212ffc04c98acbb1bc0b03d772f6803f871ded0714d97190f285b96b;
    uint256 constant betax2  = 0x244cbf5b602f5c13289976012db364615b37b13712666d2f5b1e604430ad901e;
    uint256 constant betay1  = 0x11fd065ccadbf47065681a1dc64c9024d016e55fecee762bbc143da6b3c4f3df;
    uint256 constant betay2  = 0x05fe75a8482cbe296afb8aaf1ba8db588306f1b02e998cabe5019229c8661724;
    uint256 constant gammax1 = 0x27e6b6f2fe2aae4bad7ac63b130c180a46a0cce70d559240eed4acfdb8ca5376;
    uint256 constant gammax2 = 0x24cadcbabe1d72c7c33cfb3c6076ded1b034f587e56248c5e053ca286f1bd6e5;
    uint256 constant gammay1 = 0x089a1e024e2a08b7ea7981e0e0838fce6005d8e079d76f15eee03467ccdbc315;
    uint256 constant gammay2 = 0x111d88eae49ace2265feaa1bb3aacce3193a5b2e92be6afe5ed0ebfddf3dc24d;
    uint256 constant deltax1 = 0x2319123215ffefd775717a2ce6bacae9ddbdb0fcc8b579161a4f17abb1c60973;
    uint256 constant deltax2 = 0x16567bf146ea36b8d42091d050f3fc073943a7d5153d186bc70fc833e4f72fd1;
    uint256 constant deltay1 = 0x217f313423afc6db07b9ec3f5a4c110ade912fc29cf1d03bf023cad33c3b965c;
    uint256 constant deltay2 = 0x241bd6889494718f7cc0d82d8a1072532f1b3ed08130539b6307f7b7cf1de56d;

    
    uint256 constant IC0x = 0x1daf5f77d784b61e8555585af03b58e21493dabadde0c543bcd0c4264255642c;
    uint256 constant IC0y = 0x189874445f8908888291825a87ddb2f8f0444e8f424055e4ba1822d06bf47d75;
    
    uint256 constant IC1x = 0x2c5d4c3d02de42a27c7f1695c7df15129ad68f6f001d8c20cf29de09b88c8e15;
    uint256 constant IC1y = 0x1ff42ece6e2d406e6ddf31c83de64262bbbe51a90b6c84ac76c772253f7d7590;
    
    uint256 constant IC2x = 0x14ac7b0d16a53d9f3be6e15527f26e2a9271893da56b1149c9bf2fa66c8aa8d4;
    uint256 constant IC2y = 0x2024abc1a1b96053391f8c5e09c3ded43e6e0a4aa4535427d172bd42b55b5f32;
    
    uint256 constant IC3x = 0x0db933eaed037669e2fffb07430151a4fd3d90d60e5aa4c01ee1c4a28bcebf0a;
    uint256 constant IC3y = 0x067087db8cbceecf80d1289c61f2acac4127306db7d320cc84578bea61acb808;
    
    uint256 constant IC4x = 0x07165d7f1344f011632f3b3e357dc89a8811f8853f7fc33014b1d1920bcc5f8b;
    uint256 constant IC4y = 0x29b1995228480a1777152bfe064546b36527c0914f6d2aca775c3c0ecadbc3b7;
    
    uint256 constant IC5x = 0x04df075db14b74e5b8d74c906fefdd0adb63c8ea800057677e2a1aac9cf0a53f;
    uint256 constant IC5y = 0x14718c01c47f782011821f82adcae7433b05a27e9574ceadb9f58e2613dfda95;
    
    uint256 constant IC6x = 0x05bd0eea6e01da25620cc8f6de77345ae3891fe92dfeb7096cfc3fad7764222d;
    uint256 constant IC6y = 0x03a30168e3b94a65fcef8013b5cdcb68a396d88592d03dbbd17dc11f293e5cc5;
    
    uint256 constant IC7x = 0x1c85264a51ce64c191b49e7d4c81afe28665bd60b74772c4cbe59f678cee6ed5;
    uint256 constant IC7y = 0x2138a0bf8343f56c7364fc2db431eb9471b520cc24abaca9668c6a6f094cb31b;
    
    uint256 constant IC8x = 0x078dde7f3fc34425d44a4150240b2c0d938cd46791704743cd46cc383108dd55;
    uint256 constant IC8y = 0x175f7088b1efbf7ebe101a7ab7400881b09f6483bed012c870eba1b67e3bd4fc;
    
    uint256 constant IC9x = 0x1d00e7b77a0c9111b199278f2d3a7c3374f60375a5d9c79b89dbb8b7a70f4454;
    uint256 constant IC9y = 0x16f1a859583dc0f815597092dd4eaa8cf87d8321e729da683efe660b6ab6025e;
    
    uint256 constant IC10x = 0x251eed393c0ece51b64b61a2e0632e83b00b240fd345ada0e4cf4064252dbe52;
    uint256 constant IC10y = 0x3061a90824b942a66c7bd8ffaaf93f34cc0902c989028fc5a56bf4e5e924f5f3;
    
    uint256 constant IC11x = 0x17daf18d80b54fe6c3532d6d5d0434a9102b460d35e3a6b1c114e692e3a7ebe4;
    uint256 constant IC11y = 0x038a68f7c4ab9dfe3816fc51fb2ee0be30d5c0252c57f6f193a6045b8132b13d;
    
    uint256 constant IC12x = 0x0691f4583daa26c156966e5fe871b3aeaf8a9ba16504d1efa290f90e0bdfea05;
    uint256 constant IC12y = 0x05aa3a8a851b9c301b596137883fb6bf1b4d7f235b4c89a6279467bcb6f624d9;
    
    uint256 constant IC13x = 0x035ba274b30148438a1fc538db84add5cde9b10a063c3edd55fe9bc553f72b09;
    uint256 constant IC13y = 0x2556a43cd203388278dc19e80103caa4cf0ea99253366d167082e1d59f7d73be;
    
    uint256 constant IC14x = 0x1e3f0b9864a73eb6aa0a730b7470483eea2a7a2673a0c510b1af84c0071b37a8;
    uint256 constant IC14y = 0x1f458366e281e662e2d771ec754694e54d96a67b2a06f6425ec928919697acf0;
    
    uint256 constant IC15x = 0x05359dbd3586ad7c75550f646cff4f559580ae84b3d95e7c017e6d532de62429;
    uint256 constant IC15y = 0x17720e9d75083c98e3ea8a85665fc9f3792e68ec99475975d5fdedd79e1d83b3;
    
    uint256 constant IC16x = 0x21fc47665863d2c74d53d25d5a2d86d2311fce18a9c5f752ad181f50b438423e;
    uint256 constant IC16y = 0x1601ede2c07ccfd72aaff44a669ffc916315ffcdc2044a8a685ca15d6dc1e657;
    
    uint256 constant IC17x = 0x2f81d3fe4861c3ba8699f58a54e5552234225a56c32c53440639f31c2b0b06d1;
    uint256 constant IC17y = 0x2800ab8633a82be96d05970f2aa27744cbaf7d53def1098e4c869a6d0a252afc;
    
    uint256 constant IC18x = 0x186976a31db36b82d0b639ab529263f5b18a188ce8d7ff6a0793bbb977c4caca;
    uint256 constant IC18y = 0x1918583533a838c0b376213eaaa60ac6bae67a0fe351bf188ebea88cb07dbde5;
    
    uint256 constant IC19x = 0x1515d8f808f2228879799d216ad41ecf21319979336b17f7387752e3e5efade5;
    uint256 constant IC19y = 0x24d804cb9e892c5a49e8dc8bb50be5530bbccbfd6d74b4c2c9a3e30612009422;
    
    uint256 constant IC20x = 0x1982b67155fcdb48aea52fdf9f0485d55bc7611cc31e8c56cd2fa6c5a0524604;
    uint256 constant IC20y = 0x099287c76fc8dd5d11a76cc74765ebb70c40cb08515859c5d048546abe374cb6;
    
    uint256 constant IC21x = 0x296a7efd3fb58b5c3a7bc7f7d59af5ba4a93596050732332868fde19d99986f6;
    uint256 constant IC21y = 0x17b1edd3c3d3dd248f1224cb52e6d26ca53ddd68e9e31f729bc822fd289745a6;
    
    uint256 constant IC22x = 0x0fa5a3a0694bf6a76b5ec43d6fbfc4f43017290c816c75492e55a60230ba6054;
    uint256 constant IC22y = 0x1a20993a80f7db1e70da6aa9646678cda536abfd396f0ebb7e081c607c96c182;
    
    uint256 constant IC23x = 0x0364d5ecc802ca260db3c69bccd958dc33a6b35f3afb1dd4445cce17f576e346;
    uint256 constant IC23y = 0x00d2cf8c0fe38eb5d7e5e18e3f2e2c1bbde43251d099eedf17208c300c2e9715;
    
    uint256 constant IC24x = 0x068e0e384c6ceb4bbb0e6ec9cac7663e3f4b739f2b3c2294c7d25a6bf28d4a9b;
    uint256 constant IC24y = 0x1d11ec1c9dfb5cc274257ddbec00ba59ba542b5cb1910dedcb70922447491638;
    
    uint256 constant IC25x = 0x002c16b3171f064c5898e67a30a1e89f1772949d89bca7eb074b5ce63c827dc7;
    uint256 constant IC25y = 0x268cf8da9b7c1da5507f6942cbd07735ac4c7f24ed2927a0529157c8d85b5870;
    
    uint256 constant IC26x = 0x145cbf7c327da5539579c311b8f3e32d253182a1eb8e387b447ad830d6965439;
    uint256 constant IC26y = 0x2abc9bf37820e535c91bd02e24b9710a14c4920de775c474f44ba7871781ec4d;
    
    uint256 constant IC27x = 0x1d41be5fa1475fb3b47b4ed0c1d5a6081c79a51a42d818492de004454dc47401;
    uint256 constant IC27y = 0x1394015f825d70f16f34f5c24594f1018c5a2a6713e222b9850ec95b8357cd76;
    
    uint256 constant IC28x = 0x0d6614d5f75542b13202e5f37b7d8a8602d646fd1f0694cea73b7112e1f26c7a;
    uint256 constant IC28y = 0x1a5762921a2b3f5d3c5d1065b346ccf818775f54334b46610311086d70f85fd6;
    
    uint256 constant IC29x = 0x1466ce7d12d77842273363ce0f6a0d63c54743e2e7f6be4e7569b4f9db7da370;
    uint256 constant IC29y = 0x2642bb71f854733e262c48515edb23994152c1e34816cb5aedd539d269706cb5;
    
    uint256 constant IC30x = 0x24eeac743003bc2af5e9c63c30fff065ddce2fa7fe1b6deb2380b2203e1561bb;
    uint256 constant IC30y = 0x1e4ca7a5857e2d6ea94390eec0b9c84f449afc7912d3f629163c516c573ac2b4;
    
    uint256 constant IC31x = 0x0e92ad5c9dbe2f273b4428e1932dc3cc54a59f862697090b66d6ca08e9929bc4;
    uint256 constant IC31y = 0x1e397f30c3217c595d581e60d1d8db1e36fcf274d8cd499aa4cf2d387746e982;
    
    uint256 constant IC32x = 0x2042e69e43f42c3994dd4c44d72e729b16de5f43e985c78b99d5a559ddda69b6;
    uint256 constant IC32y = 0x13d16b30285b6ebed351c4749110b122b405e983b2578694bc17c934d440f667;
    
    
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[32] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)


                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            
            return(0, 0x20)
        }
    }
}


/* =============================== */
/* Nova+CycleFold Decider verifier */
/**
 * @notice  Computes the decomposition of a `uint256` into num_limbs limbs of bits_per_limb bits each.
 * @dev     Compatible with sonobe::folding-schemes::folding::circuits::nonnative::nonnative_field_to_field_elements.
 */
library LimbsDecomposition {
    function decompose(uint256 x) internal pure returns (uint256[4] memory) {
        uint256[4] memory limbs;
        for (uint8 i = 0; i < 4; i++) {
            limbs[i] = (x >> (64 * i)) & ((1 << 64) - 1);
        }
        return limbs;
    }
}

/**
 * @author  PSE & 0xPARC
 * @title   NovaDecider contract, for verifying Nova IVC SNARK proofs.
 * @dev     This is an askama template which, when templated, features a Groth16 and KZG10 verifiers from which this contract inherits.
 */
contract NovaDecider is Groth16Verifier, KZG10Verifier {
    /**
     * @notice  Computes the linear combination of a and b with r as the coefficient.
     * @dev     All ops are done mod the BN254 scalar field prime
     */
    function rlc(uint256 a, uint256 r, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, mulmod(r, b, BN254_SCALAR_FIELD), BN254_SCALAR_FIELD)
        }
    }

    /**
     * @notice  Verifies a nova cyclefold proof consisting of two KZG proofs and of a groth16 proof.
     * @dev     The selector of this function is "dynamic", since it depends on `z_len`.
     */
    function verifyNovaProof(
        // inputs are grouped to prevent errors due stack too deep
        uint256[3] calldata i_z0_zi, // [i, z0, zi] where |z0| == |zi|
        uint256[4] calldata U_i_cmW_U_i_cmE, // [U_i_cmW[2], U_i_cmE[2]]
        uint256[2] calldata u_i_cmW, // [u_i_cmW[2]]
        uint256[3] calldata cmT_r, // [cmT[2], r]
        uint256[2] calldata pA, // groth16 
        uint256[2][2] calldata pB, // groth16
        uint256[2] calldata pC, // groth16
        uint256[4] calldata challenge_W_challenge_E_kzg_evals, // [challenge_W, challenge_E, eval_W, eval_E]
        uint256[2][2] calldata kzg_proof // [proof_W, proof_E]
    ) public view returns (bool) {

        require(i_z0_zi[0] >= 2, "Folding: the number of folded steps should be at least 2");

        // from gamma_abc_len, we subtract 1. 
        uint256[32] memory public_inputs; 

        public_inputs[0] = 0x0125a0053d0cdefcffc0c28345ea59332c2b8cbba84153a8ff9331a8fd60af7e;
        public_inputs[1] = i_z0_zi[0];

        for (uint i = 0; i < 2; i++) {
            public_inputs[2 + i] = i_z0_zi[1 + i];
        }

        {
            // U_i.cmW + r * u_i.cmW
            uint256[2] memory mulScalarPoint = super.mulScalar([u_i_cmW[0], u_i_cmW[1]], cmT_r[2]);
            uint256[2] memory cmW = super.add([U_i_cmW_U_i_cmE[0], U_i_cmW_U_i_cmE[1]], mulScalarPoint);

            {
                uint256[4] memory cmW_x_limbs = LimbsDecomposition.decompose(cmW[0]);
                uint256[4] memory cmW_y_limbs = LimbsDecomposition.decompose(cmW[1]);
        
                for (uint8 k = 0; k < 4; k++) {
                    public_inputs[4 + k] = cmW_x_limbs[k];
                    public_inputs[8 + k] = cmW_y_limbs[k];
                }
            }
        
            require(this.check(cmW, kzg_proof[0], challenge_W_challenge_E_kzg_evals[0], challenge_W_challenge_E_kzg_evals[2]), "KZG: verifying proof for challenge W failed");
        }

        {
            // U_i.cmE + r * cmT
            uint256[2] memory mulScalarPoint = super.mulScalar([cmT_r[0], cmT_r[1]], cmT_r[2]);
            uint256[2] memory cmE = super.add([U_i_cmW_U_i_cmE[2], U_i_cmW_U_i_cmE[3]], mulScalarPoint);

            {
                uint256[4] memory cmE_x_limbs = LimbsDecomposition.decompose(cmE[0]);
                uint256[4] memory cmE_y_limbs = LimbsDecomposition.decompose(cmE[1]);
            
                for (uint8 k = 0; k < 4; k++) {
                    public_inputs[12 + k] = cmE_x_limbs[k];
                    public_inputs[16 + k] = cmE_y_limbs[k];
                }
            }

            require(this.check(cmE, kzg_proof[1], challenge_W_challenge_E_kzg_evals[1], challenge_W_challenge_E_kzg_evals[3]), "KZG: verifying proof for challenge E failed");
        }

        {
            // add challenges
            public_inputs[20] = challenge_W_challenge_E_kzg_evals[0];
            public_inputs[21] = challenge_W_challenge_E_kzg_evals[1];
            public_inputs[22] = challenge_W_challenge_E_kzg_evals[2];
            public_inputs[23] = challenge_W_challenge_E_kzg_evals[3];

            uint256[4] memory cmT_x_limbs;
            uint256[4] memory cmT_y_limbs;
        
            cmT_x_limbs = LimbsDecomposition.decompose(cmT_r[0]);
            cmT_y_limbs = LimbsDecomposition.decompose(cmT_r[1]);
        
            for (uint8 k = 0; k < 4; k++) {
                public_inputs[20 + 4 + k] = cmT_x_limbs[k]; 
                public_inputs[24 + 4 + k] = cmT_y_limbs[k];
            }

            bool success_g16 = this.verifyProof(pA, pB, pC, public_inputs);
            require(success_g16 == true, "Groth16: verifying proof failed");
        }

        return(true);
    }
}