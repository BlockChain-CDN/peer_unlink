// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/**
 * @title Pairing Library for BN254 Curve
 * @dev Low-level pairing operations for Groth16 verification
 * Uses Ethereum precompiled contract at address 0x08 for bn254 pairing
 */
library Pairing {
    /// @dev Base field Fq
    uint256 constant q_mod = XX;
    
    /// @dev Scalar field Fr
    uint256 constant r_mod = XXX;
    
    /// @dev G1 point in affine coordinates
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    
    /// @dev G2 point in affine coordinates (Fq2 element)
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }
    
    /// @dev Generator for G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }
    
    /// @dev Generator for G2
    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [
                XXX,
                XXX
            ],
            [
                XXX,
                XXX
            ]
        );
    }
    
    /// @dev Check if G1 point is on curve
    function isValid(G1Point memory p) internal pure returns (bool) {
        if (p.X == 0 && p.Y == 0) return true; // Point at infinity
        
        uint256 lhs = mulmod(p.Y, p.Y, q_mod);
        uint256 rhs = mulmod(p.X, p.X, q_mod);
        rhs = mulmod(rhs, p.X, q_mod);
        rhs = addmod(rhs, 3, q_mod);
        
        return lhs == rhs;
    }
    
    /// @dev Check if G2 point is on curve
    function isValid(G2Point memory p) internal pure returns (bool) {
        if (p.X[0] == 0 && p.X[1] == 0 && p.Y[0] == 0 && p.Y[1] == 0) return true;
        
        // Fq2 arithmetic for curve equation: y^2 = x^3 + 3
        // Complex multiplication in Fq2: (a + b*i)^2 = (a^2 - b^2) + (2ab)*i
        // where i^2 = -1
        
        uint256[2] memory y2 = fq2Square(p.Y);
        uint256[2] memory x3 = fq2Cube(p.X);
        uint256[2] memory three;
        three[0] = 3;
        three[1] = 0;
        x3 = fq2Add(x3, three);
        
        return y2[0] == x3[0] && y2[1] == x3[1];
    }
    
    /// @dev Add two G1 points
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        
        bool success;
        uint256[2] memory output;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 128, output, 64)
        }
        require(success, "G1 addition failed");
        
        r.X = output[0];
        r.Y = output[1];
    }
    
    /// @dev Scalar multiplication in G1
    function scalarMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        
        bool success;
        uint256[2] memory output;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 96, output, 64)
        }
        require(success, "G1 scalar multiplication failed");
        
        r.X = output[0];
        r.Y = output[1];
    }
    
    /// @dev Negate a G1 point (negate the Y coordinate)
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        return G1Point(p.X, q_mod - p.Y);
    }
    
    /// @dev Pairing check: e(p1, p2) = e(P1, P2)^result
    /// @return result The exponent result of pairing comparison
    function pairing(G1Point memory p1, G2Point memory p2) internal view returns (bool) {
        G1Point[] memory p1Arr = new G1Point[](2);
        p1Arr[0] = p1;
        p1Arr[1] = P1();
        
        G2Point[] memory p2Arr = new G2Point[](2);
        p2Arr[0] = p2;
        p2Arr[1] = P2();
        
        return pairingProducts(p1Arr, p2Arr);
    }
    
    /// @dev Multi-pairing check: ∏ e(p1[i], p2[i]) = 1
    /// @param p1 Array of G1 points
    /// @param p2 Array of G2 points (must be same length as p1)
    /// @return success True if product of pairings equals 1
    function pairingProducts(
        G1Point[] memory p1,
        G2Point[] memory p2
    ) internal view returns (bool success) {
        require(p1.length == p2.length, "Pairing arrays must have equal length");
        require(p1.length > 0, "Pairing arrays cannot be empty");
        
        uint256 len = p1.length * 2;
        uint256[] memory input = new uint256[](len * 6);
        
        for (uint256 i = 0; i < p1.length; i++) {
            input[i * 12 + 0] = p1[i].X;
            input[i * 12 + 1] = p1[i].Y;
            input[i * 12 + 2] = p2[i].X[1]; // G2 elements are stored as (c1, c0)
            input[i * 12 + 3] = p2[i].X[0];
            input[i * 12 + 4] = p2[i].Y[1];
            input[i * 12 + 5] = p2[i].Y[0];
        }
        
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(len, 0x20), 0, 32)
        }
    }
    
    /// @dev Fq2 addition
    function fq2Add(uint256[2] memory a, uint256[2] memory b) 
        internal pure returns (uint256[2] memory) 
    {
        return [
            addmod(a[0], b[0], q_mod),
            addmod(a[1], b[1], q_mod)
        ];
    }
    
    /// @dev Fq2 subtraction
    function fq2Sub(uint256[2] memory a, uint256[2] memory b) 
        internal pure returns (uint256[2] memory) 
    {
        return [
            addmod(a[0], q_mod - b[0], q_mod),
            addmod(a[1], q_mod - b[1], q_mod)
        ];
    }
    
    /// @dev Fq2 multiplication
    function fq2Mul(uint256[2] memory a, uint256[2] memory b) 
        internal pure returns (uint256[2] memory) 
    {
        // (a0 + a1*i) * (b0 + b1*i) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*i
        uint256 a0b0 = mulmod(a[0], b[0], q_mod);
        uint256 a1b1 = mulmod(a[1], b[1], q_mod);
        uint256 a0b1 = mulmod(a[0], b[1], q_mod);
        uint256 a1b0 = mulmod(a[1], b[0], q_mod);
        
        return [
            addmod(a0b0, q_mod - a1b1, q_mod),
            addmod(a0b1, a1b0, q_mod)
        ];
    }
    
    /// @dev Fq2 squaring
    function fq2Square(uint256[2] memory a) internal pure returns (uint256[2] memory) {
        // (a0 + a1*i)^2 = (a0^2 - a1^2) + (2*a0*a1)*i
        uint256 a0Sq = mulmod(a[0], a[0], q_mod);
        uint256 a1Sq = mulmod(a[1], a[1], q_mod);
        uint256 a0a1 = mulmod(a[0], a[1], q_mod);
        
        return [
            addmod(a0Sq, q_mod - a1Sq, q_mod),
            addmod(a0a1, a0a1, q_mod)
        ];
    }
    
    /// @dev Fq2 cubing
    function fq2Cube(uint256[2] memory a) internal pure returns (uint256[2] memory) {
        return fq2Mul(fq2Mul(a, a), a);
    }
}
