// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IComputeConsumer} from "./IComputeConsumer.sol";

/// @title VerifiableComputeCoordinator
/// @notice Escrows fees for off-chain model inference and settles them against EIP-712 worker
///         attestations.
/// @dev Lifecycle:
///      1. A requester calls {requestCompute}, escrowing exactly `requestFee` and receiving a
///         request id.
///      2. An off-chain worker executes the model, hashes the output, and signs the
///         `ComputeResponse` struct with its registered key.
///      3. Anyone submits {fulfillCompute} with the attestation. The coordinator recovers the
///         signer, checks the worker registry, replay protection, model binding, and both
///         deadlines, records the output hash, pays the worker, and calls the requester back if it
///         is a contract.
///
///      The signed struct binds the request id, model id, output hash, and an attestation deadline.
///      It is scoped to this chain and this contract by the EIP-712 domain separator, so
///      attestations cannot be replayed on a fork, another deployment, or another request.
contract VerifiableComputeCoordinator is EIP712, Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    /// @notice EIP-712 type hash of the worker attestation.
    bytes32 public constant COMPUTE_RESPONSE_TYPEHASH =
        keccak256("ComputeResponse(uint256 requestId,bytes32 modelId,bytes32 outputHash,uint256 deadline)");

    /// @notice Maximum accepted input payload, bounding request gas.
    uint256 public constant MAX_INPUT_BYTES = 16_384;

    /// @notice Maximum worker endpoint length.
    uint256 public constant MAX_ENDPOINT_BYTES = 256;

    /// @notice Lower bound for the request timeout.
    uint64 public constant MIN_REQUEST_TIMEOUT = 30;

    /// @notice Upper bound for the request timeout.
    uint64 public constant MAX_REQUEST_TIMEOUT = 7 days;

    /// @notice An escrowed compute request.
    /// @param requester Address that paid for the request and receives the callback.
    /// @param modelId Model identifier the worker must attest to.
    /// @param inputHash Hash of the submitted input, retained for auditing.
    /// @param fee Amount escrowed for the worker.
    /// @param requestedAt Timestamp of submission.
    /// @param deadline Timestamp after which the request can no longer be fulfilled.
    /// @param fulfilled Whether a result was settled or the request was cancelled.
    struct ComputeRequest {
        address requester;
        bytes32 modelId;
        bytes32 inputHash;
        uint256 fee;
        uint64 requestedAt;
        uint64 deadline;
        bool fulfilled;
    }

    /// @notice Registered worker metadata.
    /// @param active Whether the worker may fulfill requests.
    /// @param registeredAt Timestamp of registration.
    /// @param endpoint Informational off-chain endpoint of the worker.
    struct Worker {
        bool active;
        uint64 registeredAt;
        string endpoint;
    }

    /// @notice Per-request escrow and settlement state.
    mapping(uint256 requestId => ComputeRequest) private _requests;

    /// @notice Worker registry keyed by signing address.
    mapping(address worker => Worker) private _workers;

    /// @notice Verified output hash per fulfilled request.
    mapping(uint256 requestId => bytes32 outputHash) public verifiedOutput;

    /// @notice Fee escrowed per request, in wei.
    uint256 public requestFee;

    /// @notice Lifetime of a request, in seconds.
    uint64 public requestTimeout;

    /// @notice Identifier that will be assigned to the next request.
    uint256 public nextRequestId = 1;

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
    event RequestCancelled(uint256 indexed requestId, address indexed requester, uint256 refund);
    event CallbackFailed(uint256 indexed requestId, address indexed consumer);
    event WorkerRegistered(address indexed worker, string endpoint);
    event WorkerStatusChanged(address indexed worker, bool active);
    event RequestFeeUpdated(uint256 fee);
    event RequestTimeoutUpdated(uint64 timeout);

    error ZeroAddress();
    error InvalidModelId();
    error EmptyInput();
    error InputTooLarge(uint256 length);
    error IncorrectFee(uint256 expected, uint256 received);
    error InvalidRequestTimeout(uint64 timeout);
    error UnknownRequest(uint256 requestId);
    error AlreadyFulfilled(uint256 requestId);
    error RequestExpired(uint256 deadline);
    error SignatureExpired(uint256 deadline);
    error ModelMismatch(bytes32 expected, bytes32 received);
    error UnauthorizedWorker(address signer);
    error UnknownWorker(address worker);
    error NotRequester(address caller);
    error InvalidSignatureLength(uint256 length);
    error FeeTransferFailed(address worker, uint256 amount);
    error EndpointTooLong(uint256 length);
    error RequestNotExpired(uint256 deadline);

    /// @param initialOwner Address allowed to manage fees and the worker registry.
    /// @param initialFee Fee escrowed per request, in wei.
    /// @param initialTimeout Request lifetime in seconds.
    constructor(address initialOwner, uint256 initialFee, uint64 initialTimeout)
        EIP712("InfernetVerifiableOracle", "1")
        Ownable(initialOwner)
    {
        if (initialOwner == address(0)) revert ZeroAddress();
        _validateTimeout(initialTimeout);
        requestFee = initialFee;
        requestTimeout = initialTimeout;
    }

    /// @notice Submits a compute request and escrows `requestFee`.
    /// @param modelId Non-zero model identifier the worker must attest to.
    /// @param inputData Non-empty input payload, bounded by {MAX_INPUT_BYTES}.
    /// @return requestId Identifier assigned to the request.
    function requestCompute(bytes32 modelId, bytes calldata inputData)
        external
        payable
        nonReentrant
        returns (uint256 requestId)
    {
        if (modelId == bytes32(0)) revert InvalidModelId();
        if (inputData.length == 0) revert EmptyInput();
        if (inputData.length > MAX_INPUT_BYTES) revert InputTooLarge(inputData.length);
        if (msg.value != requestFee) revert IncorrectFee(requestFee, msg.value);

        requestId = nextRequestId++;
        uint64 deadline = uint64(block.timestamp) + requestTimeout;

        _requests[requestId] = ComputeRequest({
            requester: msg.sender,
            modelId: modelId,
            inputHash: keccak256(inputData),
            fee: msg.value,
            requestedAt: uint64(block.timestamp),
            deadline: deadline,
            fulfilled: false
        });

        emit ComputeRequested(requestId, msg.sender, modelId, inputData);
    }

    /// @notice Settles a request against a signed worker attestation.
    /// @param requestId Request being fulfilled.
    /// @param modelId Model identifier; must equal the requested model.
    /// @param outputHash Hash of the off-chain output.
    /// @param deadline Attestation expiry timestamp.
    /// @param signature 65-byte `(r, s, v)` EIP-712 signature from an active worker.
    function fulfillCompute(
        uint256 requestId,
        bytes32 modelId,
        bytes32 outputHash,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        ComputeRequest storage request = _requests[requestId];
        if (request.requester == address(0)) revert UnknownRequest(requestId);
        if (request.fulfilled) revert AlreadyFulfilled(requestId);
        if (block.timestamp > request.deadline) revert RequestExpired(request.deadline);
        if (block.timestamp > deadline) revert SignatureExpired(deadline);
        if (modelId != request.modelId) revert ModelMismatch(request.modelId, modelId);
        if (signature.length != 65) revert InvalidSignatureLength(signature.length);

        bytes32 digest = hashResponse(requestId, modelId, outputHash, deadline);
        address signer = ECDSA.recover(digest, signature);
        Worker storage worker = _workers[signer];
        if (!worker.active) revert UnauthorizedWorker(signer);

        request.fulfilled = true;
        verifiedOutput[requestId] = outputHash;

        emit ComputeFulfilled(requestId, signer, modelId, outputHash, request.fee);

        uint256 fee = request.fee;
        if (fee > 0) {
            (bool paid,) = signer.call{value: fee}("");
            if (!paid) revert FeeTransferFailed(signer, fee);
        }

        address consumer = request.requester;
        if (consumer.code.length > 0) {
            try IComputeConsumer(consumer).onComputeResult(requestId, modelId, outputHash) {}
            catch {
                emit CallbackFailed(requestId, consumer);
            }
        }
    }

    /// @notice Reclaims the escrow of a request that was never fulfilled after its deadline.
    /// @param requestId Request to cancel.
    function cancelRequest(uint256 requestId) external nonReentrant {
        ComputeRequest storage request = _requests[requestId];
        if (request.requester == address(0)) revert UnknownRequest(requestId);
        if (request.fulfilled) revert AlreadyFulfilled(requestId);
        if (msg.sender != request.requester) revert NotRequester(msg.sender);
        if (block.timestamp <= request.deadline) revert RequestNotExpired(request.deadline);

        request.fulfilled = true;
        uint256 refund = request.fee;
        emit RequestCancelled(requestId, request.requester, refund);

        if (refund > 0) {
            (bool refunded,) = request.requester.call{value: refund}("");
            if (!refunded) revert FeeTransferFailed(request.requester, refund);
        }
    }

    /// @notice Registers a new active worker.
    /// @param worker Signing address of the worker.
    /// @param endpoint Informational endpoint, at most {MAX_ENDPOINT_BYTES} bytes.
    function registerWorker(address worker, string calldata endpoint) external onlyOwner {
        if (worker == address(0)) revert ZeroAddress();
        if (bytes(endpoint).length > MAX_ENDPOINT_BYTES) revert EndpointTooLong(bytes(endpoint).length);
        _workers[worker] =
            Worker({active: true, registeredAt: uint64(block.timestamp), endpoint: endpoint});
        emit WorkerRegistered(worker, endpoint);
        emit WorkerStatusChanged(worker, true);
    }

    /// @notice Enables or disables an already registered worker.
    /// @param worker Worker address.
    /// @param active Whether the worker may fulfill requests.
    function setWorkerActive(address worker, bool active) external onlyOwner {
        Worker storage entry = _workers[worker];
        if (entry.registeredAt == 0) revert UnknownWorker(worker);
        entry.active = active;
        emit WorkerStatusChanged(worker, active);
    }

    /// @notice Updates the per-request fee. Applies to requests submitted afterwards.
    /// @param newFee New fee in wei.
    function setRequestFee(uint256 newFee) external onlyOwner {
        requestFee = newFee;
        emit RequestFeeUpdated(newFee);
    }

    /// @notice Updates the request lifetime.
    /// @param newTimeout New lifetime in seconds, within the allowed bounds.
    function setRequestTimeout(uint64 newTimeout) external onlyOwner {
        _validateTimeout(newTimeout);
        requestTimeout = newTimeout;
        emit RequestTimeoutUpdated(newTimeout);
    }

    /// @notice Returns the EIP-712 digest a worker must sign for a given response.
    /// @dev Exposed so off-chain workers and integrators can cross-check their hashing.
    function hashResponse(uint256 requestId, bytes32 modelId, bytes32 outputHash, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(COMPUTE_RESPONSE_TYPEHASH, requestId, modelId, outputHash, deadline))
        );
    }

    /// @notice Returns the EIP-712 domain separator of this deployment.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Returns the stored request.
    /// @param requestId Request identifier.
    function getRequest(uint256 requestId) external view returns (ComputeRequest memory) {
        return _requests[requestId];
    }

    /// @notice Returns the worker registry entry.
    /// @param worker Worker address.
    function getWorker(address worker) external view returns (Worker memory) {
        return _workers[worker];
    }

    /// @notice Whether an address is a registered, active worker.
    /// @param worker Worker address.
    function isActiveWorker(address worker) external view returns (bool) {
        return _workers[worker].active;
    }

    /// @notice Whether a request has been settled or cancelled.
    /// @param requestId Request identifier.
    function isFulfilled(uint256 requestId) external view returns (bool) {
        return _requests[requestId].fulfilled;
    }

    function _validateTimeout(uint64 timeout) private pure {
        if (timeout < MIN_REQUEST_TIMEOUT || timeout > MAX_REQUEST_TIMEOUT) {
            revert InvalidRequestTimeout(timeout);
        }
    }
}
