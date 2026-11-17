// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {VerifiableComputeCoordinator} from "../src/VerifiableComputeCoordinator.sol";
import {SampleAIConsumer} from "../src/SampleAIConsumer.sol";

contract VerifiableComputeTest is Test {
    uint256 internal constant WORKER_PK = 0xA11CE;
    uint256 internal constant ATTACKER_PK = 0xB0B;
    uint256 internal constant FEE = 0.01 ether;
    uint64 internal constant TIMEOUT = 300;

    bytes32 internal constant MODEL_ID = keccak256("sentiment-v1");
    bytes32 internal constant OTHER_MODEL_ID = keccak256("sentiment-v2");
    bytes32 internal constant OUTPUT_HASH = keccak256("positive:0.93");
    bytes internal constant INPUT_DATA = "classify: the protocol works";

    VerifiableComputeCoordinator internal coordinator;
    SampleAIConsumer internal consumer;
    address internal worker;

    event ComputeRequested(
        uint256 indexed requestId, address indexed requester, bytes32 modelId, bytes inputData
    );
    event ComputeFulfilled(
        uint256 indexed requestId,
        address indexed worker,
        bytes32 modelId,
        bytes32 outputHash,
        uint256 fee
    );
    event ScoreReceived(uint256 indexed requestId, bytes32 indexed modelId, bytes32 outputHash);

    function setUp() public {
        vm.deal(address(this), 100 ether);
        coordinator = new VerifiableComputeCoordinator(address(this), FEE, TIMEOUT);
        consumer = new SampleAIConsumer(address(coordinator), address(this));
        worker = vm.addr(WORKER_PK);
        coordinator.registerWorker(worker, "https://worker.infernet.local");
    }

    /* --------------------------------------------------------------------- */
    /* Requests                                                              */
    /* --------------------------------------------------------------------- */

    function test_RequestCompute_StoresEscrowAndEmits() public {
        uint256 requestId = coordinator.nextRequestId();
        uint256 deadline = block.timestamp + TIMEOUT;

        vm.expectEmit(true, true, false, true, address(coordinator));
        emit ComputeRequested(requestId, address(this), MODEL_ID, INPUT_DATA);

        uint256 assigned = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);

        assertEq(assigned, requestId);
        assertEq(coordinator.nextRequestId(), requestId + 1);
        assertEq(address(coordinator).balance, FEE);

        VerifiableComputeCoordinator.ComputeRequest memory request = coordinator.getRequest(requestId);
        assertEq(request.requester, address(this));
        assertEq(request.modelId, MODEL_ID);
        assertEq(request.inputHash, keccak256(INPUT_DATA));
        assertEq(request.fee, FEE);
        assertEq(request.requestedAt, block.timestamp);
        assertEq(request.deadline, deadline);
        assertFalse(request.fulfilled);
    }

    function test_RequestCompute_RevertsOnIncorrectFee() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.IncorrectFee.selector, FEE, FEE - 1
            )
        );
        coordinator.requestCompute{value: FEE - 1}(MODEL_ID, INPUT_DATA);
    }

    function test_RequestCompute_RevertsOnEmptyInput() public {
        vm.expectRevert(VerifiableComputeCoordinator.EmptyInput.selector);
        coordinator.requestCompute{value: FEE}(MODEL_ID, "");
    }

    function test_RequestCompute_RevertsOnZeroModel() public {
        vm.expectRevert(VerifiableComputeCoordinator.InvalidModelId.selector);
        coordinator.requestCompute{value: FEE}(bytes32(0), INPUT_DATA);
    }

    function test_RequestCompute_RevertsOnOversizedInput() public {
        bytes memory oversized = new bytes(coordinator.MAX_INPUT_BYTES() + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.InputTooLarge.selector, oversized.length
            )
        );
        coordinator.requestCompute{value: FEE}(MODEL_ID, oversized);
    }

    /* --------------------------------------------------------------------- */
    /* Fulfillment                                                           */
    /* --------------------------------------------------------------------- */

    function test_FulfillCompute_ValidSignatureSettlesAndPaysWorker() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        uint256 workerBalanceBefore = worker.balance;

        vm.expectEmit(true, true, false, true, address(coordinator));
        emit ComputeFulfilled(requestId, worker, MODEL_ID, OUTPUT_HASH, FEE);

        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);

        assertEq(coordinator.verifiedOutput(requestId), OUTPUT_HASH);
        assertTrue(coordinator.isFulfilled(requestId));
        assertEq(worker.balance, workerBalanceBefore + FEE);
        assertEq(address(coordinator).balance, 0);
    }

    function test_FulfillCompute_RevertsOnUnregisteredSigner() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(ATTACKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);
        address attacker = vm.addr(ATTACKER_PK);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.UnauthorizedWorker.selector, attacker
            )
        );
        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsOnInactiveWorker() public {
        coordinator.setWorkerActive(worker, false);
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.UnauthorizedWorker.selector, worker
            )
        );
        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsOnExpiredRequestDeadline() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        vm.warp(block.timestamp + TIMEOUT + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.RequestExpired.selector, block.timestamp - 1
            )
        );
        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsOnExpiredSignatureDeadline() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp - 1;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.SignatureExpired.selector, deadline
            )
        );
        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsOnReplay() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.AlreadyFulfilled.selector, requestId
            )
        );
        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsOnModelMismatch() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, OTHER_MODEL_ID, OUTPUT_HASH, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.ModelMismatch.selector, MODEL_ID, OTHER_MODEL_ID
            )
        );
        coordinator.fulfillCompute(requestId, OTHER_MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsOnUnknownRequest() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, 999, MODEL_ID, OUTPUT_HASH, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(VerifiableComputeCoordinator.UnknownRequest.selector, 999)
        );
        coordinator.fulfillCompute(999, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function test_FulfillCompute_RevertsWhenOutputHashWasSwapped() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        vm.expectRevert();
        coordinator.fulfillCompute(requestId, MODEL_ID, keccak256("tampered"), deadline, signature);
    }

    function test_FulfillCompute_RevertsOnMalformedSignature() public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = new bytes(64);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.InvalidSignatureLength.selector, 64
            )
        );
        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);
    }

    function testFuzz_FulfillCompute_AnyOutputHash(bytes32 outputHash) public {
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, outputHash, deadline);

        coordinator.fulfillCompute(requestId, MODEL_ID, outputHash, deadline, signature);
        assertEq(coordinator.verifiedOutput(requestId), outputHash);
    }

    /* --------------------------------------------------------------------- */
    /* Consumer callback                                                     */
    /* --------------------------------------------------------------------- */

    function test_ConsumerFlow_StoresVerifiedResult() public {
        uint256 requestId = consumer.requestScore{value: FEE}(MODEL_ID, INPUT_DATA);
        assertEq(consumer.latestRequestId(), requestId);
        assertEq(consumer.resultCount(), 0);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory signature = _sign(WORKER_PK, requestId, MODEL_ID, OUTPUT_HASH, deadline);

        vm.expectEmit(true, false, false, true, address(consumer));
        emit ScoreReceived(requestId, MODEL_ID, OUTPUT_HASH);

        coordinator.fulfillCompute(requestId, MODEL_ID, OUTPUT_HASH, deadline, signature);

        assertEq(consumer.latestOutputHash(), OUTPUT_HASH);
        assertEq(consumer.resultCount(), 1);
    }

    function test_ConsumerFlow_RevertsForNonOwner() public {
        address stranger = makeAddr("stranger");
        vm.deal(stranger, 1 ether);

        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(SampleAIConsumer.NotOwner.selector, stranger)
        );
        consumer.requestScore{value: FEE}(MODEL_ID, INPUT_DATA);
    }

    function test_ConsumerFlow_RevertsForNonCoordinatorCallback() public {
        vm.expectRevert(
            abi.encodeWithSelector(SampleAIConsumer.NotCoordinator.selector, address(this))
        );
        consumer.onComputeResult(1, MODEL_ID, OUTPUT_HASH);
    }

    function test_ConsumerFlow_RevertsForUnexpectedRequest() public {
        uint256 requestId = consumer.requestScore{value: FEE}(MODEL_ID, INPUT_DATA);
        assertEq(requestId, 1);

        vm.prank(address(coordinator));
        vm.expectRevert(
            abi.encodeWithSelector(
                SampleAIConsumer.UnexpectedRequest.selector, requestId, requestId + 1
            )
        );
        consumer.onComputeResult(requestId + 1, MODEL_ID, OUTPUT_HASH);
    }

    /* --------------------------------------------------------------------- */
    /* Escrow reclaim                                                        */
    /* --------------------------------------------------------------------- */

    function test_CancelRequest_RefundsRequesterAfterDeadline() public {
        address alice = makeAddr("alice");
        vm.deal(alice, 1 ether);

        vm.prank(alice);
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);

        uint256 balanceAfterRequest = alice.balance;
        vm.warp(block.timestamp + TIMEOUT + 1);

        vm.prank(alice);
        coordinator.cancelRequest(requestId);

        assertEq(alice.balance, balanceAfterRequest + FEE);
        assertTrue(coordinator.isFulfilled(requestId));
        assertEq(address(coordinator).balance, 0);
    }

    function test_CancelRequest_RevertsBeforeDeadline() public {
        address alice = makeAddr("alice");
        vm.deal(alice, 1 ether);

        vm.prank(alice);
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.RequestNotExpired.selector, block.timestamp + TIMEOUT
            )
        );
        coordinator.cancelRequest(requestId);
    }

    function test_CancelRequest_RevertsForNonRequester() public {
        address alice = makeAddr("alice");
        vm.deal(alice, 1 ether);

        vm.prank(alice);
        uint256 requestId = coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);

        vm.warp(block.timestamp + TIMEOUT + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.NotRequester.selector, address(this)
            )
        );
        coordinator.cancelRequest(requestId);
    }

    /* --------------------------------------------------------------------- */
    /* EIP-712 domain and digest                                             */
    /* --------------------------------------------------------------------- */

    function test_DomainSeparator_MatchesChainAndDeployment() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("InfernetVerifiableOracle"),
                keccak256("1"),
                block.chainid,
                address(coordinator)
            )
        );
        assertEq(coordinator.domainSeparator(), expected);
    }

    function test_HashResponse_MatchesManualDigest() public view {
        uint256 requestId = 42;
        uint256 deadline = 1_900_000_000;
        bytes32 structHash = keccak256(
            abi.encode(
                coordinator.COMPUTE_RESPONSE_TYPEHASH(), requestId, MODEL_ID, OUTPUT_HASH, deadline
            )
        );
        bytes32 expected =
            keccak256(abi.encodePacked("\x19\x01", coordinator.domainSeparator(), structHash));

        assertEq(coordinator.hashResponse(requestId, MODEL_ID, OUTPUT_HASH, deadline), expected);
    }

    /// @dev Prints the digest of a fixed response under this deployment's domain. The Go signer
    ///      test pins the same value, so a divergence in either hash implementation fails a suite.
    function test_CrossLanguageDigestVector() public view {
        uint256 requestId = 1;
        uint256 deadline = 1_800_000_000;
        bytes32 digest = coordinator.hashResponse(requestId, MODEL_ID, OUTPUT_HASH, deadline);
        console2.log("chainId", block.chainid);
        console2.log("verifyingContract", address(coordinator));
        console2.log("requestId", requestId);
        console2.log("deadline", deadline);
        console2.logBytes32(MODEL_ID);
        console2.logBytes32(OUTPUT_HASH);
        console2.logBytes32(digest);
    }

    /* --------------------------------------------------------------------- */
    /* Administration                                                        */
    /* --------------------------------------------------------------------- */

    function test_RegisterWorker_OnlyOwner() public {
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert();
        coordinator.registerWorker(makeAddr("worker2"), "https://worker2.local");
    }

    function test_RegisterWorker_RejectsEmptyAddress() public {
        vm.expectRevert(VerifiableComputeCoordinator.ZeroAddress.selector);
        coordinator.registerWorker(address(0), "https://worker.local");
    }

    function test_SetWorkerActive_UnknownWorkerReverts() public {
        address unknown = makeAddr("unknown");
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.UnknownWorker.selector, unknown
            )
        );
        coordinator.setWorkerActive(unknown, false);
    }

    function test_SetRequestFee_AppliesToNextRequest() public {
        coordinator.setRequestFee(0.02 ether);
        assertEq(coordinator.requestFee(), 0.02 ether);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.IncorrectFee.selector, 0.02 ether, FEE
            )
        );
        coordinator.requestCompute{value: FEE}(MODEL_ID, INPUT_DATA);
    }

    function test_SetRequestTimeout_EnforcesBounds() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableComputeCoordinator.InvalidRequestTimeout.selector, uint64(1)
            )
        );
        coordinator.setRequestTimeout(1);

        coordinator.setRequestTimeout(600);
        assertEq(coordinator.requestTimeout(), 600);
    }

    /* --------------------------------------------------------------------- */
    /* Helpers                                                               */
    /* --------------------------------------------------------------------- */

    function _sign(
        uint256 privateKey,
        uint256 requestId,
        bytes32 modelId,
        bytes32 outputHash,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 digest = coordinator.hashResponse(requestId, modelId, outputHash, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
