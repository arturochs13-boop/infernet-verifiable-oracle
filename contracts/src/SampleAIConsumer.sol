// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IComputeConsumer} from "./IComputeConsumer.sol";
import {VerifiableComputeCoordinator} from "./VerifiableComputeCoordinator.sol";

/// @title SampleAIConsumer
/// @notice Reference consumer that requests an inference score and stores the verified result.
/// @dev The consumer forwards the exact fee it receives, so callers must send the coordinator's
///      current `requestFee()`. Only the coordinator may deliver results.
contract SampleAIConsumer is IComputeConsumer {
    /// @notice Coordinator this consumer is bound to.
    VerifiableComputeCoordinator public immutable coordinator;

    /// @notice Address allowed to submit scoring requests.
    address public immutable owner;

    /// @notice Most recent request id submitted by this consumer.
    uint256 public latestRequestId;

    /// @notice Model of the most recent request.
    bytes32 public latestModelId;

    /// @notice Hash of the most recent verified output.
    bytes32 public latestOutputHash;

    /// @notice Number of verified results received.
    uint256 public resultCount;

    event ScoreRequested(uint256 indexed requestId, bytes32 indexed modelId, bytes inputData);
    event ScoreReceived(uint256 indexed requestId, bytes32 indexed modelId, bytes32 outputHash);

    error ZeroAddress();
    error NotOwner(address caller);
    error NotCoordinator(address caller);
    error UnexpectedRequest(uint256 expected, uint256 received);

    /// @param coordinator_ Coordinator address.
    /// @param owner_ Address allowed to submit requests.
    constructor(address coordinator_, address owner_) {
        if (coordinator_ == address(0) || owner_ == address(0)) revert ZeroAddress();
        coordinator = VerifiableComputeCoordinator(payable(coordinator_));
        owner = owner_;
    }

    /// @notice Requests a score for `inputData` under `modelId`, forwarding the attached fee.
    /// @param modelId Model identifier.
    /// @param inputData Input payload for the model.
    /// @return requestId Coordinator-assigned request id.
    function requestScore(bytes32 modelId, bytes calldata inputData)
        external
        payable
        returns (uint256 requestId)
    {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        requestId = coordinator.requestCompute{value: msg.value}(modelId, inputData);

        latestRequestId = requestId;
        latestModelId = modelId;

        emit ScoreRequested(requestId, modelId, inputData);
    }

    /// @inheritdoc IComputeConsumer
    function onComputeResult(uint256 requestId, bytes32 modelId, bytes32 outputHash) external {
        if (msg.sender != address(coordinator)) revert NotCoordinator(msg.sender);
        if (requestId != latestRequestId) revert UnexpectedRequest(latestRequestId, requestId);

        latestOutputHash = outputHash;
        resultCount += 1;

        emit ScoreReceived(requestId, modelId, outputHash);
    }
}
