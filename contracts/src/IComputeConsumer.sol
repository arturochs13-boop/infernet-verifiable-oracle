// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IComputeConsumer
/// @notice Callback implemented by contracts that consume verified compute results.
/// @dev The coordinator calls this after the worker attestation has been verified and the fee has
///      been released. Implementations must authenticate `msg.sender` as the coordinator.
interface IComputeConsumer {
    /// @notice Receives a verified compute result.
    /// @param requestId Identifier of the originating request.
    /// @param modelId Model that produced the output.
    /// @param outputHash Hash of the off-chain output, attested by the worker.
    function onComputeResult(uint256 requestId, bytes32 modelId, bytes32 outputHash) external;
}
