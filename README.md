# infernet-verifiable-oracle

Verifiable on-chain/off-chain AI compute bridge using Solidity EIP-712 attestations and a Go
execution worker.

A consumer contract escrows a fee and emits a compute request. An off-chain Go worker runs a
deterministic model, hashes the output, and signs an EIP-712 `ComputeResponse` with a key registered
on-chain. Anyone can submit that attestation; the coordinator verifies the signature, binds it to the
request and model, enforces replay protection and deadlines, records the output hash, pays the
worker, and calls the consumer back. No trusted RPC, no oracle committee, no off-chain database.

---

## Lifecycle

```
  Consumer contract / EOA                     VerifiableComputeCoordinator                    Go worker
  ─────────────────────────                   ────────────────────────────────                ─────────
          │                                              │                                      │
          │  requestCompute(modelId, inputData)          │                                      │
          │  + fee (escrowed)                            │                                      │
          ├─────────────────────────────────────────────▶│                                      │
          │                                              │  ComputeRequested(id, requester,     │
          │                                              │    modelId, inputData)               │
          │                                              ├─────────────── event ───────────────▶│
          │                                              │                                      │
          │                                              │        execute deterministic model   │
          │                                              │        outputHash = keccak256(out)   │
          │                                              │        sign EIP-712 ComputeResponse  │
          │                                              │◀────────── fulfillCompute(...) ──────┤
          │                                              │                                      │
          │                       verify domain + struct hash, recover signer                   │
          │                       require active worker, deadline, modelId, !fulfilled          │
          │                                              │                                      │
          │◀──── onComputeResult(id, modelId, outputHash)│─────────── fee ──────────────────────▶│
          │      (try/catch, failure emits event)        │                                      │
```

1. **Request.** `requestCompute(bytes32 modelId, bytes inputData)` requires a non-zero model id, a
   non-empty input of at most 16 KiB, and exactly `requestFee` in `msg.value`. The request id,
   requester, input hash, fee, and deadline are stored and the full input is emitted for workers.
2. **Execute.** The worker polls `ComputeRequested`, runs the deterministic scoring executor, and
   builds `outputHash = keccak256(output)`.
3. **Attest.** The worker signs
   `ComputeResponse(uint256 requestId, bytes32 modelId, bytes32 outputHash, uint256 deadline)` using
   the coordinator's EIP-712 domain (`InfernetVerifiableOracle`, version `1`, chain id, contract
   address).
4. **Settle.** `fulfillCompute` checks request existence, replay, the request deadline, the
   attestation deadline, and model binding, then recovers the signer with `ECDSA.recover`. Only an
   active registered worker may settle. The fee is released, and the requester is called back if it
   is a contract.
5. **Cancel.** If no worker settles before the request deadline, the requester reclaims the escrow
   with `cancelRequest`.

---

## Security model

| Property | Mechanism |
| --- | --- |
| Attestation authenticity | ECDSA over an EIP-712 digest; the signer must be a registered active worker. |
| Cross-chain / cross-contract replay | Domain separator binds `chainId` and `verifyingContract`. |
| Cross-request replay | `requestId` is inside the signed struct and `fulfilled[requestId]` blocks reuse. |
| Cross-model substitution | `modelId` is signed and compared to the stored request. |
| Stale attestations | Signed `deadline` plus a separate on-chain request deadline. |
| Worker key rotation | Owner enables/disables workers without touching escrow. |
| Reentrancy | `nonReentrant` on request, fulfill, and cancel; state is written before transfers. |
| Consumer callback failure | `try/catch` around the callback; settlement still completes and `CallbackFailed` is emitted. |
| Stuck escrow | `cancelRequest` refunds the requester after the deadline. |
| Input DoS | Inputs are capped at 16 KiB; fee and timeout are bounded by the owner. |

**Trust assumptions.** The owner registers workers; a compromised worker key can attest arbitrary
outputs for requests it fulfills. The protocol proves *who* attested *which* output for *which*
request — it does not prove the model was executed correctly. To close that gap, compare
`outputHash` against a re-execution by another worker, or extend the attestation with a ZK/TEE proof.

---

## Repository layout

```
infernet-verifiable-oracle/
├── contracts/
│   ├── src/
│   │   ├── VerifiableComputeCoordinator.sol   # EIP-712 settlement, escrow, worker registry
│   │   ├── SampleAIConsumer.sol               # reference consumer storing verified results
│   │   └── IComputeConsumer.sol               # callback interface
│   ├── test/VerifiableCompute.t.sol           # 31 Foundry tests
│   └── foundry.toml
└── worker/
    ├── cmd/worker/main.go                     # --dry-run and --listen CLI
    └── pkg/
        ├── signer/eip712.go                   # byte-identical EIP-712 hashing and signing
        ├── signer/eip712_test.go              # pinned cross-language vector
        └── engine/executor.go                 # deterministic inference pipeline
```

### EIP-712 construction

```
domainSeparator = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("InfernetVerifiableOracle"),
    keccak256("1"),
    chainId,
    verifyingContract))

structHash = keccak256(abi.encode(
    keccak256("ComputeResponse(uint256 requestId,bytes32 modelId,bytes32 outputHash,uint256 deadline)"),
    requestId, modelId, outputHash, deadline))

digest = keccak256(0x1901 ‖ domainSeparator ‖ structHash)
```

The Solidity suite prints the digest for a fixed response under a deterministic deployment, and the
Go suite pins the same constant. Either implementation drifting breaks a test suite.

---

## Run the tests

```bash
# Solidity
cd contracts
forge test -vvv

# Go
cd worker
go test -v ./...
go vet ./...
```

Expected: **31 Foundry tests** and **15 Go tests**, all passing.

---

## Worker CLI

```bash
cd worker
go build -o bin/worker ./cmd/worker
```

### Dry run: sign locally, print calldata

```bash
./bin/worker --dry-run \
  --chain-id 31337 \
  --coordinator 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
  --worker-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  --request-id 1 \
  --input "classify: the protocol works"
```

Output includes the model output, `inputHash`, `outputHash`, digest, 65-byte signature with
`v ∈ {27, 28}`, and ABI-encoded `fulfillCompute` calldata.

### Listen: fulfill requests from a node

```bash
./bin/worker --listen \
  --rpc http://127.0.0.1:8545 \
  --coordinator 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
  --chain-id 31337 \
  --worker-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  --from-block 0 \
  --poll-interval 1s
```

The listener verifies the node's chain id, checks that the coordinator has code, refuses to start
unless the worker key is registered and active, backfills from `--from-block` (or the current head
when omitted), skips already-fulfilled requests, estimates gas, submits the transaction, and waits
for a successful receipt. `SIGINT`/`SIGTERM` shut it down cleanly.

### Local end-to-end walkthrough

```bash
anvil --port 8545 --chain-id 31337

forge create src/VerifiableComputeCoordinator.sol:VerifiableComputeCoordinator \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast \
  --constructor-args 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 10000000000000000 300

cast send $COORDINATOR "registerWorker(address,string)" \
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8 "https://worker.local" \
  --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

cast send $COORDINATOR "requestCompute(bytes32,bytes)" \
  0xbb90cdb04ca02199f9d23b4e77f96238eea6d61fa0bc900568885e13b5af55fe \
  0x636c6173736966793a207468652070726f746f636f6c20776f726b73 \
  --value 0.01ether \
  --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

cd worker && go run ./cmd/worker --listen --from-block 0 ... # as above
cast call $COORDINATOR "verifiedOutput(uint256)(bytes32)" 1 --rpc-url http://127.0.0.1:8545
```

The final call returns the same hash the worker printed in dry-run mode; `getRequest(1)` shows
`fulfilled = true`.

---

## Deterministic executor

`DeterministicExecutor` derives a score in `[0, 10000]` from the first eight bytes of
`keccak256(input)`, assigns a label at 5000/8000 basis points, and serializes a fixed-order JSON
document. It is deliberately not a trained model: it makes the off-chain computation reproducible so
the attestation is meaningful and testable. Implement the `Executor` interface to plug in a real
model; keep the output hashing and attestation path unchanged.

---

## Design notes

- **Checks-Effects-Interactions.** Fulfillment marks the request settled and stores the output before
  the fee transfer and consumer callback.
- **Custom errors** for every failure path, with NatSpec on all external functions.
- **Strict inputs.** Wrong fee, empty input, oversized input, zero model, malformed signature length,
  and unknown requests all fail closed.
- **No hardcoded secrets.** The worker takes its key from flags; use a secret manager in production.
- **Two independent hash implementations.** Solidity and Go agree on a pinned digest vector.

---

## License

MIT
