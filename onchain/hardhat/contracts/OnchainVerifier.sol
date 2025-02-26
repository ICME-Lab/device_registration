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
    uint256 constant alphax  = 0x2bcb07e090c509648460310ef6e09672b1f3a802f8f6afcd5b560ebc8dfed400;
    uint256 constant alphay  = 0x1c2d0b45b0ea4b29d9ec33c5bd4ca4051d136bc9c27c417d1ce735c8865f7d8d;
    uint256 constant betax1  = 0x170bef003071274cf9c722c4a2ec8825cd56327bdb311e929ba9c19c64bd2b93;
    uint256 constant betax2  = 0x04c196246635e807257b64025d1da2f3d497f10f70ca9f9e14014d70985e1811;
    uint256 constant betay1  = 0x0cd90adfe289ba215558d896ee457af9708af3c0c6133d61a0cd907e92782292;
    uint256 constant betay2  = 0x196faee2853f78c04d354e9b0c2ff38f5b3e4dbc2ce3c6bc79755aca3163c44f;
    uint256 constant gammax1 = 0x118591cd5f93db67a738b3bd1556a7c5a116c5eddff9c7f9d7fb0d3297ed3d3d;
    uint256 constant gammax2 = 0x10226223146e0333ac07a3026a095213b10aab8a51a69112004a6243c070be53;
    uint256 constant gammay1 = 0x08d524789251ea760d321556433b9df73389cc6310afdbe037237780f106234c;
    uint256 constant gammay2 = 0x0e50609f485f6635911ca9685614f031713af9768d2b317dfedc99569353b5fe;
    uint256 constant deltax1 = 0x2edd92a231b4a44dcad9e185f8c7778a31a0b32a9c97be302d7009250dcfb23e;
    uint256 constant deltax2 = 0x1bf9ad1a92c8d86777ca41065a4fef9225d3ae380e6055617c6c51177003d51e;
    uint256 constant deltay1 = 0x07f8c3c3b1285dcba6a185f08eeed9498df70bfa7a69af3ffa8d3fc24152cd68;
    uint256 constant deltay2 = 0x23cceedea3653120adf7889d4ff94a427450e8bba3deede2443c752388775fda;

    
    uint256 constant IC0x = 0x0f8087d78fd3a13a9551931f3b55398f864454fe608e861546c590e110ce2020;
    uint256 constant IC0y = 0x26728a8140b0c67542590f90e0a88cb92e3d6213cf5453fec32e7778a785d5e8;
    
    uint256 constant IC1x = 0x11010d9c6e38fa7c3cf45810cf9f531f458f567048e95539963fa9711c739175;
    uint256 constant IC1y = 0x018ccd0277cd1b06c9d2130b73f047c28f6ee4753a037754d3822b71fab25f4a;
    
    uint256 constant IC2x = 0x198fe48d9eb27296e4d46c93838ed990cfeddeace4ff225688cb36b82ec42717;
    uint256 constant IC2y = 0x0485afca2daab6776d99aa26b27c474e7529ca01b1ad0be331a49e6c5571447b;
    
    uint256 constant IC3x = 0x1f13a3fe67c7727d8a0335bc1c15fc2b764e5bd95daf0081c34cfd8dee47875f;
    uint256 constant IC3y = 0x229c0a86659cf518a997bbb20276ae50b93aba41373084e38bc70c4f6b45a0ce;
    
    uint256 constant IC4x = 0x1967416ceb3a4beb17e6ad4b4cdb175da60c26fcbb8086d1c45588be6cd6eae4;
    uint256 constant IC4y = 0x1a22199e40346c8b01f07fa3be60cb695a950b9b3f023ad02d70a212dc4a7b41;
    
    uint256 constant IC5x = 0x1cd400afadce3d551aa765bfd507b4e32ad1449facdf798f29fd1329fccb1350;
    uint256 constant IC5y = 0x15e80f197e156bfc612be47582fe9963f9d0396b4a4c545aaea48eb0d7330b87;
    
    uint256 constant IC6x = 0x23de5e0cf0d193985bb1f5e4eaf05a3d1411e932c6385fb906a116cb7afab8c9;
    uint256 constant IC6y = 0x0a337e439f9058771097f19f2ab0fd3e298e38dd432ee2206d239ecdb9ab15fb;
    
    uint256 constant IC7x = 0x1b2c4dc7aadd5c5615cfbec2193c72eec4351f6388962a398d6318ee94684b0f;
    uint256 constant IC7y = 0x29b039e1766ccc319311e0a2418c8c6b61e2e7048c12fc038a969753d8b13f05;
    
    uint256 constant IC8x = 0x06a78a92f313fee6dfac403a8ca45110ba3c1d779469a93a74962ff0e51ab4d2;
    uint256 constant IC8y = 0x2f43fac8c2c2dab2041d82d998c81e664872120d19664344a4db0e8fd293b99d;
    
    uint256 constant IC9x = 0x01cb1c4a07e2108684351408498b8259e7ae34214f54db065f7fa090ebea6aea;
    uint256 constant IC9y = 0x1f9785dc9f5562990187842a69793e9bf0a33ebac57224a593781a97ddafe947;
    
    uint256 constant IC10x = 0x04acdd3175587ad1dca2b0577dced9b765f1cce61209905fd467eb23bf3c6ebb;
    uint256 constant IC10y = 0x2499ba0dc99e8af0dd56ecb56b922f5478f83803c34cdcbf9fcc994df915341a;
    
    uint256 constant IC11x = 0x0711f2a71684b202a430e7dbf85431d15a2bb54ee16eeebd496eab3994074b16;
    uint256 constant IC11y = 0x14ae7c51cce8d46b87997a393ba565285227d1e639e7fa32bfdbdd377902a308;
    
    uint256 constant IC12x = 0x23330a0ae1259ace2f28ad040bf2e0c77504a413c2ff82638cb4b3cf647f3cda;
    uint256 constant IC12y = 0x27bceeb635df7332f9618d74565686ca6ec61aa24f0acdb09cff7e3a215b9bfa;
    
    uint256 constant IC13x = 0x20303fce6392875c09ca31b2894778446424475fec4e23b20af0cd4aaa6487fe;
    uint256 constant IC13y = 0x2568f820c814c94a40744b6f171fcd34cbe98b3a46299583fb4fb3634fcfb506;
    
    uint256 constant IC14x = 0x287947ba205e2ba1d5174b136e93848e50f104b5c802bdf0c3c62088cc223561;
    uint256 constant IC14y = 0x17c233346c6b4aaf4accf74881746ff097edf954aa4318e6ac89aefa4edef275;
    
    uint256 constant IC15x = 0x0e650541e9d2ec1d43807215375199f5a5ee2ebf4a5d3adf31fe93aae2f37965;
    uint256 constant IC15y = 0x15fad1251cb10082ad4e2528ea8ca77aa738ec5e86bb7b3adffa3e59c46b9e13;
    
    uint256 constant IC16x = 0x15590df5329bf6e99e6408770870d5ef1874c610416cd1d761b0c22cd0ee62d4;
    uint256 constant IC16y = 0x1778b105a18c2910177a284eff8c0455b04bf1eb6610321ec03861dba6f5062b;
    
    uint256 constant IC17x = 0x17bf4d437010bee75009e5e1142dbeb4fd8e1bcfaa7d622083608786e0dc516e;
    uint256 constant IC17y = 0x24fff15b6df784700f53380202335d1b730c4f2785f3ebf9c9c04e5c5a9fe2b1;
    
    uint256 constant IC18x = 0x08e006f7d5fe8f935d858885b8ebfaca99a13267e381f23108f134c17d78d39e;
    uint256 constant IC18y = 0x21892acceb9ba86650e4216ff30c077f2261c023e240d95ffb7346ac02513f82;
    
    uint256 constant IC19x = 0x263a958dc60569351ec7b99c5b144788bfec258cba37987e5abbbe6c34024f83;
    uint256 constant IC19y = 0x063f51092a1138e56509c3312ccc8601feb633646e8bc55b2c1808ffd258799d;
    
    uint256 constant IC20x = 0x1ce127bc75a2766c47f2aaed7e153731df98b92a0f983c912727c4a034078f7e;
    uint256 constant IC20y = 0x1bdab421c58a7fda6a41fb161c294b8c5ffaf7e2ba6fbc71cfc852bfeb10d867;
    
    uint256 constant IC21x = 0x185654525df54e91acc61c25647550698884a5f90a363d8dce3c73685837a239;
    uint256 constant IC21y = 0x16070596f4d1ae539bb992a236f3c9fe1febe33a7f0dabea87e6ea66cd76f47b;
    
    uint256 constant IC22x = 0x0170434e55af68cf14aba84d5a6201bf4459908f4272ed31ed74647595f8a5a5;
    uint256 constant IC22y = 0x1e7ce3133949ea40a0441e3b0767e17d48a192d94752fda196bcd9cf55ba8d24;
    
    uint256 constant IC23x = 0x002b0e212e9f118c89478d3fdf9d77c0f9941760d4217ef45dfc2daedaf7edc4;
    uint256 constant IC23y = 0x050090d0e9f95d287260387b80c5126a7e391a9638cc98e5ae9ffc86f3e72c10;
    
    uint256 constant IC24x = 0x11b9321b72aad9b82450e03336453e13d5688d3180a64139c73619b8f18cee6c;
    uint256 constant IC24y = 0x08d574dfa32e40352abaca79905afea14f0c25f650076b9dfb8b3b9ce670b802;
    
    uint256 constant IC25x = 0x2eae40c0aa87ffbb66bc10056e07c74a03d40266e0fffc1145d1a0c108bcfddf;
    uint256 constant IC25y = 0x1fd345fa97ba4246a0e5bdb19e7702b85f039fdfb7108bb91da02b46863378ea;
    
    uint256 constant IC26x = 0x07182515694d14480866446e299fe8ef8e526868062365ef6f22717bb2773734;
    uint256 constant IC26y = 0x0c8545960481b22a260411aaf88e79fbeda4915c83486be1b7182733d41a8c96;
    
    uint256 constant IC27x = 0x0b4f5d9df420fdae60d9e119f9b4cc27c10ed0778706e78a33d529a28bedacef;
    uint256 constant IC27y = 0x14743a7006b2405669e1a1a5e67535da2da0f6ca8cf96e0b70463eaaae6c3508;
    
    uint256 constant IC28x = 0x1cd803e77e85858819bff62686255b41df102895bc8e78e49d09557d384e3a1f;
    uint256 constant IC28y = 0x1e3121d260c6d9f91ff59435159f1e9db0fc35ad97cfda64194a2bc051e74a89;
    
    uint256 constant IC29x = 0x0488f90b11633501d63cba615b9fadff16e17e62d9ae5a63042b4ec05d851006;
    uint256 constant IC29y = 0x12aee098b3466c531da162e87e2354c5eafe265e00b2180968ce9ce450bd258f;
    
    uint256 constant IC30x = 0x004da33fa9998640d59f84629a8d0de5cf7f211bcbea72cbaffa0c92c5bb3d62;
    uint256 constant IC30y = 0x0f5203253ac1c168418a5708fc65f53e2efc8f599a6cb6943d8bf72318dde264;
    
    uint256 constant IC31x = 0x2fb25dcc3dd96e6e137261213f9a05c4d710e63e10eea32e9b06436bc4053e1d;
    uint256 constant IC31y = 0x0b260d90f09a1ccf7a42baa2113982af1df5d1d7290527f3720671fba819892c;
    
    uint256 constant IC32x = 0x0c9b526a00bdbd1e7031f3aae102dc8ddc653a153156f6426ffc7545bf88ec7e;
    uint256 constant IC32y = 0x048dacc60ffc2bd58b94bc051329fa03e919aa4ff1bc74cfdfd5994a3a293c10;
    
    
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

        public_inputs[0] = 0x03e7c5722d93171f795ffbc5b16f516c129b53d4b2881240dbfb5465143aced1;
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