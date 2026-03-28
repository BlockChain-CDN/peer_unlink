// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {FTSU} from "./FairThunder_Stream_Utility.sol";

contract FairStreamingUnlinking {
    
    // State variables
    uint public H_gen;
    bytes32 public root_com;
    mapping(bytes32 => bool) public SpentList;
    uint public T_receive;
    uint public T_finish;
    bytes public pk_P_eph;
    bytes public pk_d_eph;
    bytes public pk_c_eph;
    bool public provider_verified;
    bool public deliverer_verified;
    bool public consumer_verified;
    uint public register_time_deliverer;
    uint public register_time_consumer;
    
    enum State { started, joined, ready, initiated, received, payingDelivery, payingRevealing, sold, not_sold }
    State public currentState;
    
    bytes32 public root_m;
    uint public n;
    uint public payment_P;
    uint public payment_C;
    bool public plt;
    uint public ctr;
    uint public ctr_D;
    uint public ctr_P;
    
    bytes public sid;
    uint public K;
    bytes32 public Nul_p;
    bytes32 public Nul_c;
    uint256 public stakeThreshold;
    address public zkVerifier;
    
    // Staking
    mapping(address => uint256) public stakeBalances;
    mapping(bytes32 => bool) public commitments;
    
    // GPLP Settlement
    mapping(bytes32 => uint256) public sessionDebts;
    mapping(bytes32 => bytes32) public com_temp;
    
    // Setup: receive stake deposit from p, d, or c
    function setup(uint256 stake, bytes32 com) payable public {
        require(msg.value == stake, "Stake amount must match deposit");
        require(stake >= stakeThreshold, "Stake below threshold");
        require(com != bytes32(0), "Commitment cannot be zero");
        
        stakeBalances[msg.sender] += stake;
        commitments[com] = true;
        
        // Insert com into global staking pool Merkle tree MT_com and update root_com
        // For simplicity, we hash the current root with new commitment
        root_com = keccak256(abi.encodePacked(root_com, com));
    }
    
    function deriveAddressFromEphemeralKey(bytes memory _pk_eph) internal pure returns (address payable) {
        bytes32 pk_hash = keccak256(_pk_eph);
        return payable(address(uint160(uint256(pk_hash))));
    }
    
    modifier onlyDeliverer() {
        require(msg.sender == deriveAddressFromEphemeralKey(pk_d_eph), "Only deliverer can call this");
        _;
    }
    
    function inState(State s) internal {
        currentState = s;
        T_receive = block.timestamp + 10 minutes;
    }
    
    
    constructor(address _zkVerifier) payable {
        H_gen = block.number;
        zkVerifier = _zkVerifier;
        currentState = State.started;
    }
    
    // Phase I: Provider initiates session
    function start(
        uint256 stake, 
        bytes memory _pk_P_eph,
        bytes32 _Nul_p,
        bytes32 _root_m,
        uint _n,
        uint _payment_P,
        uint _payment_C,
        uint _K,
        uint256 _stakeThreshold,
        bytes32 _com_temp_p
    ) payable public {
        require(msg.value >= _payment_P * _n + stake, "Insufficient payment for chunks and stake");
        require(_pk_P_eph.length == 64, "Ephemeral key must be 64 bytes");
        require(_root_m != bytes32(0), "Root commitment cannot be zero");
        require(_com_temp_p != bytes32(0), "Temporary commitment cannot be zero");
        require(currentState == State.started, "Invalid state: expected started");
        
        // Assert contract state Γ ≡ ∅ (empty/uninitialized)
        require(H_gen == 0 || H_gen == block.number, "Contract already initialized");
        
        // Store parameters as per design
        pk_P_eph = _pk_P_eph;
        Nul_p = _Nul_p;
        root_m = _root_m;
        n = _n;
        payment_P = _payment_P;
        payment_C = _payment_C;
        K = _K;
        stakeThreshold = _stakeThreshold;
        
        // Store Nul_p and let SpentList[Nul_p] = false
        SpentList[_Nul_p] = false;
        
        // Store temporary commitment for provider
        com_temp[_Nul_p] = _com_temp_p;
        
        // Record provider's stake balance
        stakeBalances[deriveAddressFromEphemeralKey(_pk_P_eph)] = stake;
        
        // Mark provider as verified
        provider_verified = true;
        
        // Let Γ = started and send (started, ...) to all
        currentState = State.started;
        T_receive = block.timestamp + 10 minutes;
    }
    
    // Phase I: Deliverer joins
    function join(
        bytes memory _pk_d_eph
    ) public {
        require(currentState == State.started, "Invalid state");
        require(_pk_d_eph.length == 64, "Ephemeral key must be 64 bytes");
        
        pk_d_eph = _pk_d_eph;
        register_time_deliverer = block.timestamp;
        deliverer_verified = true;
        
        currentState = State.joined;
    }
    
    // Phase I: Transition to ready
    function prepared() public {
        require(T_receive > block.timestamp, "Timeout exceeded");
        require(currentState == State.joined, "Invalid state");
        currentState = State.ready;
    }
    
    // Phase II: Consumer joins and starts streaming
    function consume(
        uint T_c,
        bytes32 _Nul_c,
        bytes32 _com_temp_c
    ) payable public {
        require(currentState == State.ready, "Invalid state: expected ready");
        require(T_c > 0, "Invalid time parameter");
        require(_com_temp_c != bytes32(0), "Temporary commitment cannot be zero");
        require(msg.value >= payment_C * n, "Insufficient payment for content chunks");
        
        // Assert T_c is consistent with T (computed via H_gen, K, and latest block height)
        // T should be computable as: T = H_gen + K * ceil((block.number - H_gen) / K)
        uint expected_T = H_gen + K * ((block.number - H_gen + K - 1) / K);
        require(T_c == expected_T, "Inconsistent time parameter");
        
        // Store Nul_c and let SpentList[Nul_c] = false
        Nul_c = _Nul_c;
        SpentList[_Nul_c] = false;
        
        // Store temporary commitment for consumer
        com_temp[_Nul_c] = _com_temp_c;
        
        // Store consumer's ephemeral key for later derivation
        pk_c_eph = abi.encodePacked(msg.sender);
        
        register_time_consumer = block.timestamp;
        consumer_verified = true;
        
        // Start two timers: T_receive and T_finish
        T_receive = block.timestamp + 20 minutes;
        T_finish = block.timestamp + 30 minutes;
        
        // Let Γ = initiated and send (initiated, T_c, Nul_c) to all
        currentState = State.initiated;
    }
    
    // Phase II: Consumer confirms data received
    function received() public {
        require(block.timestamp < T_receive, "Receive timeout exceeded");
        require(currentState == State.initiated, "Invalid state");
        currentState = State.received;
    }
    
    // Phase II: Trigger receive timeout
    function receiveTimeout() public {
        require(block.timestamp >= T_receive, "Timeout not yet reached");
        require(currentState == State.initiated, "Invalid state");
        currentState = State.received;
    }
    
    // Phase III: Deliverer claims payment
    function claimDelivery(
        FTSU.Groth16Proof calldata proof,
        FTSU.ZKStatement calldata statement,
        uint _i,
        bytes calldata signature
    ) public {
        require(block.timestamp < T_finish, "Timeout exceeded");
        require(currentState == State.received, "Invalid state");
        require(deliverer_verified, "Deliverer not verified");
        require(_i <= n, "Invalid chunk index");
        require(ctr_D == 0, "Already claimed");
        require(!SpentList[statement.Nul], "Nullifier already spent");
        
        // ZK verification
        require(
            FTSU.ZKVerify(zkVerifier, statement, proof),
            "ZK proof verification failed"
        );
        
        // Validate consumer signature
        bytes32 receipt_message = FTSU.prefixed(
            keccak256(abi.encodePacked("delivery_receipt", _i, sid))
        );
        address consumer_addr = deriveAddressFromEphemeralKey(pk_c_eph);
        address signer = FTSU.recoverSigner(receipt_message, signature);
        require(signer == consumer_addr, "Invalid consumer signature");
        
        // Verify statement matches contract state
        require(statement.root_m == root_m, "Invalid root_m");
        require(statement.stakeThreshold == stakeThreshold, "Invalid stake threshold");
        
        // Mark nullifier as spent
        SpentList[statement.Nul] = true;
        
        // Update counter: ctr_d = i
        ctr_D = _i;
        currentState = State.payingDelivery;
    }
    
    // Phase III: Provider claims payment
    function claimRevealing(
        FTSU.Groth16Proof calldata proof,
        FTSU.ZKStatement calldata statement,
        uint _j,
        bytes calldata signature
    ) public {
        require(block.timestamp < T_finish, "Timeout exceeded");
        require(currentState == State.received, "Invalid state");
        require(provider_verified, "Provider not verified");
        require(_j <= n, "Invalid chunk index");
        require(ctr_P == 0, "Already claimed");
        require(!SpentList[statement.Nul], "Nullifier already spent");
        
        // ZK verification
        require(
            FTSU.ZKVerify(zkVerifier, statement, proof),
            "ZK proof verification failed"
        );
        
        // Validate provider signature
        bytes32 receipt_message = FTSU.prefixed(
            keccak256(abi.encodePacked("revealing_receipt", _j, sid))
        );
        address provider_addr = deriveAddressFromEphemeralKey(pk_P_eph);
        address signer = FTSU.recoverSigner(receipt_message, signature);
        require(signer == provider_addr, "Invalid provider signature");
        
        // Verify statement matches contract state
        require(statement.root_m == root_m, "Invalid root_m");
        require(statement.stakeThreshold == stakeThreshold, "Invalid stake threshold");
        
        // Mark nullifier as spent
        SpentList[statement.Nul] = true;
        
        // Update counter: ctr_p = j
        ctr_P = _j;
        currentState = State.payingRevealing;
    }
    
    // Phase III: Finalize payout with GPLP-based settlement
    function finishTimeout() public {
        require(block.timestamp >= T_finish, "Timeout not yet reached");
        
        // Determine final counter: ctr = max{ctr_P, ctr_D}
        ctr = (ctr_D >= ctr_P) ? ctr_D : ctr_P;
        
        // Calculate session debt for consumer: sessionDebts[Nul_c] = β_c * ctr
        sessionDebts[Nul_c] = payment_C * ctr;
        
        // Assert neither nullifier has been spent
        require(SpentList[Nul_p] == false, "Provider nullifier already spent");
        require(SpentList[Nul_c] == false, "Consumer nullifier already spent");
        
        // Mark nullifiers as spent
        SpentList[Nul_p] = true;
        SpentList[Nul_c] = true;
        
        // Calculate commitments for GPLP Merkle tree
        // com_d = H(com_temp_d || (β_p * ctr))
        bytes32 com_d = keccak256(abi.encodePacked(com_temp[Nul_p], payment_P * ctr));
        
        // com_p = H(com_temp_p || ((β_c - β_p) * ctr))
        bytes32 com_p = keccak256(abi.encodePacked(com_temp[Nul_c], (payment_C - payment_P) * ctr));
        
        // TODO: Insert com_d and com_p into GPLP Merkle tree MT_com
        // TODO: Update root_com accordingly
        // For now, we simulate by hashing the new roots
        root_com = keccak256(abi.encodePacked(root_com, com_d, com_p));
        
        // Set final state based on delivery outcome
        if (ctr > 0) {
            currentState = State.sold;
        } else {
            currentState = State.not_sold;
        }
    }
    
    // ========== RESET FOR NEXT SESSION ==========

    function reset() public {
        require(provider_verified, "Provider not verified");
        require(currentState == State.sold || currentState == State.not_sold, "Invalid state for reset");
        
        // Reset counters
        ctr = 0;
        ctr_D = 0;
        ctr_P = 0;
        
        // Clear timeouts
        T_receive = 0;
        T_finish = 0;
        
        // Clear consumer-specific state
        pk_c_eph = "";
        consumer_verified = false;
        register_time_consumer = 0;
        
        // Return to ready state
        currentState = State.ready;
    }
    
    function updateEphemeralDelivererAddress(
        address payable _newDelivererAddress,
        bytes memory _signature
    ) public onlyDeliverer {
        require(_newDelivererAddress != address(0), "Invalid deliverer address");
        require(consumer_verified, "Consumer not verified");
        
        bytes32 confirmation_message = FTSU.prefixed(
            keccak256(abi.encodePacked(
                "confirmNextDeliverer",
                msg.sender,
                _newDelivererAddress,
                address(this)
            ))
        );
        
        require(FTSU.verifyEphemeralSignature(confirmation_message, _signature, pk_c_eph), "Invalid signature");
        
        pk_d_eph = abi.encodePacked(_newDelivererAddress);
    }
    
    // ========== UTILITY FUNCTIONS ==========
    
    function getStateString() public view returns (string memory) {
        if (currentState == State.started) return "started";
        if (currentState == State.joined) return "joined";
        if (currentState == State.ready) return "ready";
        if (currentState == State.initiated) return "initiated";
        if (currentState == State.received) return "received";
        if (currentState == State.payingDelivery) return "payingDelivery";
        if (currentState == State.payingRevealing) return "payingRevealing";
        if (currentState == State.sold) return "sold";
        if (currentState == State.not_sold) return "not_sold";
        return "unknown";
    }
    
    /**
     * @dev Check if nullifier has been spent
     */
    function isNullifierSpent(bytes32 nul) public view returns (bool) {
        return SpentList[nul];
    }
    
    /**
     * @dev Withdraw remaining staking after session completion
     * Consumer can withdraw: initial_stake - sessionDebts[Nul_c]
     */
    function withdrawRemainingStake(bytes32 _Nul) public {
        require(currentState == State.sold || currentState == State.not_sold, "Session not finalized");
        require(SpentList[_Nul] == true, "Nullifier not spent yet");
        require(sessionDebts[_Nul] > 0 || _Nul == Nul_p, "No recorded debt for this nullifier");
        
        uint256 initialStake = stakeBalances[msg.sender];
        require(initialStake > 0, "No stake balance");
        
        uint256 debt = sessionDebts[_Nul];
        uint256 remaining = initialStake > debt ? initialStake - debt : 0;
        
        require(remaining > 0, "No remaining stake to withdraw");
        
        // Clear the debt record to prevent double withdrawal
        sessionDebts[_Nul] = 0;
        
        // Transfer remaining stake
        (bool success, ) = payable(msg.sender).call{value: remaining}("");
        require(success, "Withdrawal transfer failed");
    }
}
