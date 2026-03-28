// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

/**
 * @title FairThunderStreamUtility
 * @dev Utility library for FairThunder streaming protocol with ZK-SNARK support
 */
library FTSU {
    
    /**
     * @dev Merkle proof structure
     */
    struct MerkleProof {
        bytes32 label; // the hash value of the sibling
        uint posIden;  // the binary bit indicating the position
    }

    /**
     * @dev Simplified proof structure for ephemeral key ownership
     */
    struct Proof {
        bytes32 commitment; // hash commitment of the ephemeral key with private key proof
    }
    
    /**
     * @dev Groth16 Proof structure for ZK-SNARK verification
     * Following the standard format: π = (A, B, C) where:
     * - A ∈ G1
     * - B ∈ G2  
     * - C ∈ G1
     */
    struct Groth16Proof {
        uint256[2] A;  // G1 point
        uint256[2][2] B; // G2 point (uncompressed)
        uint256[2] C;  // G1 point
    }
    
    /**
     * @dev Verification Key structure for Groth16
     */
    struct VerificationKey {
        uint256[2] alpha;  // G1
        uint256[2][2] beta; // G2
        uint256[2] gamma;  // G1
        uint256[2] delta;  // G1
        uint256[2][] IC;   // G1 elements for public inputs
    }
    
    /**
     * @dev ZK Statement public inputs
     * Corresponds to x = (EEID, Nul, root_m, T, root_com, ฿^thre)
     */
    struct ZKStatement {
        bytes EEID;           // Ephemeral Extended Identifier (pk^eph)
        bytes32 Nul;          // Nullifier to prevent double spending
        bytes32 root_m;       // Merkle root of data chunks
        uint256 T;            // Timestamp/block height
        bytes32 root_com;     // Root of staking commitment Merkle tree
        uint256 stakeThreshold; // Minimum stake threshold (฿^thre)
    }
    
    /**
     * @dev Witness data (private, only known to prover)
     * Corresponds to w = (sk^mas, MTP, r, ฿^sta)
     */
    struct ZKWitness {
        bytes32 masterSecret; // sk^mas - master secret key
        bytes merkleProof;    // MTP - Merkle tree proof
        bytes32 randomness;   // r - random nonce
        uint256 stakeAmount;  // ฿^sta - staked amount
    }
    
    /**
     * @dev Split signature into v, r, s components
     */
    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }
    
    /**
     * @dev Recover the signer address from message hash and signature
     */
    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "Invalid signature v value");
        address signer = ecrecover(message, v, r, s);
        require(signer != address(0), "Invalid signature");
        return signer;
    }
    
    /**
     * @dev Prefix a hash with Ethereum signed message header (EIP-191)
     */
    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Simplified verification of ephemeral key ownership
     * Just verify that the commitment is valid (hash of ephemeral key)
     */
    function verifyEphemeralKeyOwnership(
        bytes memory _pk_eph,
        Proof memory _proof,
        bytes32 _public_input
    ) internal pure returns (bool) {
        require(_pk_eph.length == 64, "Ephemeral key must be 64 bytes");
        
        // Simple verification: check if commitment matches the public input
        bytes32 expected_commitment = keccak256(abi.encodePacked(_pk_eph, _public_input));
        return _proof.commitment == expected_commitment;
    }

    /**
     * @dev Verify a message was signed with the ephemeral key using ECDSA
     */
    function verifyEphemeralSignature(
        bytes32 _message,
        bytes memory _signature,
        bytes memory _pk_eph
    ) internal pure returns (bool) {
        require(_pk_eph.length == 64, "Ephemeral key must be 64 bytes");
        require(_signature.length == 65, "Signature must be 65 bytes");
        
        // Extract v, r, s from signature
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        require(v == 27 || v == 28, "Invalid signature v value");
        
        // Recover signer
        address recovered = ecrecover(_message, v, r, s);
        require(recovered != address(0), "Invalid signature");
        
        // Hash ephemeral key to derive expected address
        bytes32 pk_hash = keccak256(_pk_eph);
        address expected_addr = address(uint160(uint256(pk_hash)));
        
        return recovered == expected_addr;
    }

    /**
     * @dev Verify a Merkle proof
     */
    function verifyMerkleProof(
        bytes32 _leaf,
        bytes32 _root,
        MerkleProof[] memory _proof
    ) internal pure returns (bool) {
        bytes32 computedHash = _leaf;

        for (uint256 i = 0; i < _proof.length; i++) {
            bytes32 proofElement = _proof[i].label;
            
            if (_proof[i].posIden == 0) {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            } else {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            }
        }

        return computedHash == _root;
    }

    /**
     * @dev Hash commitment to a message with ephemeral key
     * @param _message The message
     * @param _pk_eph The ephemeral public key
     * @param _nonce A nonce for uniqueness
     * @return The commitment hash
     */
    function hashCommitment(
        bytes memory _message,
        bytes memory _pk_eph,
        uint _nonce
    ) internal pure returns (bytes32) {
        require(_pk_eph.length == 64, "Ephemeral key must be 64 bytes");
        return keccak256(abi.encodePacked(_message, _pk_eph, _nonce));
    }
    
    /**
     * @dev Compute commitment from witness data
     * Relation: com = H(sk^mas||฿^sta||r)
     * @param witness The witness data containing master secret, stake, and randomness
     * @return The commitment hash
     */
    function computeCommitment(ZKWitness memory witness) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                witness.masterSecret,
                witness.stakeAmount,
                witness.randomness
            )
        );
    }
    
    /**
     * @dev Derive ephemeral secret key from master secret
     * Relation: sk^eph = H(sk^mas||root_m||T||r||"sk")
     * @param masterSecret Master secret key (sk^mas)
     * @param root_m Merkle root of data
     * @param timestamp Time parameter T
     * @param randomness Random nonce r
     * @return Derived ephemeral secret key hash
     */
    function deriveEphemeralSecret(
        bytes32 masterSecret,
        bytes32 root_m,
        uint256 timestamp,
        bytes32 randomness
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                masterSecret,
                root_m,
                timestamp,
                randomness,
                "sk"
            )
        );
    }
    
    /**
     * @dev Compute nullifier to prevent double spending
     * Relation: Nul = H(sk^mas||root_m||T||r||"null")
     * @param masterSecret Master secret key (sk^mas)
     * @param root_m Merkle root of data
     * @param timestamp Time parameter T
     * @param randomness Random nonce r
     * @return Computed nullifier
     */
    function computeNullifier(
        bytes32 masterSecret,
        bytes32 root_m,
        uint256 timestamp,
        bytes32 randomness
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                masterSecret,
                root_m,
                timestamp,
                randomness,
                "null"
            )
        );
    }
    
    /**
     * @dev Perform Groth16 zero-knowledge proof verification
     * Relation: {0,1} <- ZKVerify(vk_NIZK, x, pi_auth)
     * 
     * @param verifier The Groth16 verifier contract address
     * @param statement Public inputs x = (EEID, Nul, root_m, T, root_com, stakeThreshold)
     * @param proof Groth16 proof pi = (A, B, C)
     * @return true if proof verifies successfully
     * 
     * @notice This calls an external verifier contract generated by Circom/circomsnarkjs
     *         Gas cost: ~250,000-350,000 depending on number of public inputs
     */
    function ZKVerify(
        address verifier,
        ZKStatement memory statement,
        Groth16Proof memory proof
    ) internal view returns (bool) {
        require(verifier != address(0), "Invalid verifier address");
        require(statement.EEID.length == 64, "EEID must be 64 bytes");
        
        // Encode public inputs for the circuit
        // Format depends on how the circuit was compiled
        // Typical format: [constant_term, EEID_x, EEID_y, Nul, root_m, T, root_com, stakeThreshold]
        uint256[] memory publicInputs = new uint256[](8);
        
        // EEID is a G1 point (64 bytes = 2 x 32 bytes)
        bytes32 EEID_x = bytes32(statement.EEID);
        bytes32 EEID_y = bytes32(statement.EEID);
        
        publicInputs[0] = 1; // Constant term (always 1)
        publicInputs[1] = uint256(EEID_x);
        publicInputs[2] = uint256(EEID_y);
        publicInputs[3] = uint256(statement.Nul);
        publicInputs[4] = uint256(statement.root_m);
        publicInputs[5] = statement.T;
        publicInputs[6] = uint256(statement.root_com);
        publicInputs[7] = statement.stakeThreshold;
        
        // Call the external verifier contract
        bool isValid = IGroth16Verifier(verifier).verify(
            proof.A,
            proof.B,
            proof.C,
            publicInputs
        );
        
        return isValid;
    }
    
    /**
     * @dev Verify Merkle tree proof for stake commitment
     * Relation: VerifyMTP(com, MTP, root_com) = 1
     * @param leaf The leaf node (commitment)
     * @param proof Merkle proof array
     * @param root Expected Merkle root
     * @return true if proof is valid
     */
    function verifyStakeMerkleProof(
        bytes32 leaf,
        MerkleProof[] memory proof,
        bytes32 root
    ) internal pure returns (bool) {
        return verifyMerkleProof(leaf, root, proof);
    }
}

/**
 * @dev Interface for Groth16 verifier contract
 */
interface IGroth16Verifier {
    function verify(
        uint256[2] calldata proof_A,
        uint256[2][2] calldata proof_B,
        uint256[2] calldata proof_C,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}