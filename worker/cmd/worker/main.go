// Command worker runs an off-chain executor for VerifiableComputeCoordinator.
//
// Two modes are supported:
//
//	--dry-run   execute the model, sign the EIP-712 attestation, and print the ABI-encoded
//	            fulfillCompute calldata without touching a node.
//	--listen    poll a JSON-RPC node for ComputeRequested events, execute each request, and submit
//	            the signed fulfillment transaction from the worker account.
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/arturochs13-boop/infernet-verifiable-oracle/worker/pkg/engine"
	"github.com/arturochs13-boop/infernet-verifiable-oracle/worker/pkg/signer"
)

const coordinatorABI = `[
  {
    "type": "event",
    "name": "ComputeRequested",
    "anonymous": false,
    "inputs": [
      {"name": "requestId", "type": "uint256", "indexed": true},
      {"name": "requester", "type": "address", "indexed": true},
      {"name": "modelId", "type": "bytes32", "indexed": false},
      {"name": "inputData", "type": "bytes", "indexed": false}
    ]
  },
  {
    "type": "function",
    "name": "fulfillCompute",
    "stateMutability": "nonpayable",
    "inputs": [
      {"name": "requestId", "type": "uint256"},
      {"name": "modelId", "type": "bytes32"},
      {"name": "outputHash", "type": "bytes32"},
      {"name": "deadline", "type": "uint256"},
      {"name": "signature", "type": "bytes"}
    ],
    "outputs": []
  },
  {
    "type": "function",
    "name": "getRequest",
    "stateMutability": "view",
    "inputs": [{"name": "requestId", "type": "uint256"}],
    "outputs": [
      {"name": "requester", "type": "address"},
      {"name": "modelId", "type": "bytes32"},
      {"name": "inputHash", "type": "bytes32"},
      {"name": "fee", "type": "uint256"},
      {"name": "requestedAt", "type": "uint64"},
      {"name": "deadline", "type": "uint64"},
      {"name": "fulfilled", "type": "bool"}
    ]
  },
  {
    "type": "function",
    "name": "isActiveWorker",
    "stateMutability": "view",
    "inputs": [{"name": "worker", "type": "address"}],
    "outputs": [{"name": "active", "type": "bool"}]
  }
]`

type config struct {
	listen          bool
	dryRun          bool
	rpcURL          string
	coordinator     string
	workerKey       string
	chainID         uint64
	requestID       uint64
	modelID         string
	input           string
	attestationTTL  time.Duration
	pollInterval    time.Duration
	fromBlock       int64
	coordinatorAddr common.Address
	modelIDBytes    [32]byte
	privateKey      *ecdsa.PrivateKey
	contract        abi.ABI
}

type attestationReport struct {
	Mode        string          `json:"mode"`
	Signer      string          `json:"signer"`
	ChainID     uint64          `json:"chain_id"`
	Coordinator string          `json:"coordinator"`
	RequestID   uint64          `json:"request_id"`
	ModelID     string          `json:"model_id"`
	InputHash   string          `json:"input_hash"`
	OutputHash  string          `json:"output_hash"`
	Output      json.RawMessage `json:"output"`
	Deadline    uint64          `json:"deadline"`
	Digest      string          `json:"digest"`
	Signature   string          `json:"signature"`
	Calldata    string          `json:"calldata"`
}

type computeRequestedEvent struct {
	RequestID *big.Int       `abi:"requestId"`
	Requester common.Address `abi:"requester"`
	ModelID   [32]byte       `abi:"modelId"`
	InputData []byte         `abi:"inputData"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "worker: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.dryRun {
		return runDryRun(ctx, cfg)
	}
	return runListener(ctx, cfg)
}

func parseConfig(args []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("worker", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.BoolVar(&cfg.listen, "listen", false, "poll the node for ComputeRequested events and fulfill them")
	flags.BoolVar(&cfg.dryRun, "dry-run", false, "execute and sign locally, printing calldata without submitting")
	flags.StringVar(&cfg.rpcURL, "rpc", "http://127.0.0.1:8545", "JSON-RPC endpoint")
	flags.StringVar(&cfg.coordinator, "coordinator", "", "coordinator contract address (required)")
	flags.StringVar(&cfg.workerKey, "worker-key", "", "worker private key in hex (required)")
	flags.Uint64Var(&cfg.chainID, "chain-id", 31337, "chain id the coordinator is deployed on")
	flags.Uint64Var(&cfg.requestID, "request-id", 1, "request id to fulfill in dry-run mode")
	flags.StringVar(&cfg.modelID, "model-id", "0xbb90cdb04ca02199f9d23b4e77f96238eea6d61fa0bc900568885e13b5af55fe", "model id (bytes32 hex)")
	flags.StringVar(&cfg.input, "input", "classify: the protocol works", "input payload for dry-run execution")
	flags.DurationVar(&cfg.attestationTTL, "attestation-ttl", time.Hour, "validity window of a signed attestation")
	flags.DurationVar(&cfg.pollInterval, "poll-interval", 2*time.Second, "event polling interval")
	flags.Int64Var(&cfg.fromBlock, "from-block", -1, "first block to scan; negative starts at the current head")

	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if cfg.listen == cfg.dryRun {
		return config{}, errors.New("exactly one of --listen or --dry-run is required")
	}
	if cfg.coordinator == "" {
		return config{}, errors.New("--coordinator is required")
	}
	if cfg.workerKey == "" {
		return config{}, errors.New("--worker-key is required")
	}
	if !common.IsHexAddress(cfg.coordinator) {
		return config{}, fmt.Errorf("invalid coordinator address %q", cfg.coordinator)
	}
	cfg.coordinatorAddr = common.HexToAddress(cfg.coordinator)

	modelID, err := parseBytes32(cfg.modelID)
	if err != nil {
		return config{}, fmt.Errorf("invalid --model-id: %w", err)
	}
	cfg.modelIDBytes = modelID

	key, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.workerKey, "0x"))
	if err != nil {
		return config{}, fmt.Errorf("invalid --worker-key: %w", err)
	}
	cfg.privateKey = key

	if cfg.attestationTTL <= 0 {
		return config{}, errors.New("--attestation-ttl must be positive")
	}
	if cfg.pollInterval <= 0 {
		return config{}, errors.New("--poll-interval must be positive")
	}
	if cfg.fromBlock < -1 {
		return config{}, errors.New("--from-block must be non-negative or -1")
	}

	contract, err := abi.JSON(strings.NewReader(coordinatorABI))
	if err != nil {
		return config{}, fmt.Errorf("parsing coordinator ABI: %w", err)
	}
	cfg.contract = contract
	return cfg, nil
}

func runDryRun(ctx context.Context, cfg config) error {
	executor := engine.DeterministicExecutor{}
	result, err := executor.Execute(ctx, engine.Request{
		RequestID: new(big.Int).SetUint64(cfg.requestID),
		ModelID:   cfg.modelIDBytes,
		Input:     []byte(cfg.input),
	})
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}

	deadline := new(big.Int).SetInt64(time.Now().Add(cfg.attestationTTL).Unix())
	report, err := buildAttestation(cfg, result, deadline)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	fmt.Println(string(encoded))
	return nil
}

func buildAttestation(cfg config, result engine.Result, deadline *big.Int) (attestationReport, error) {
	domain := signer.NewDomain(new(big.Int).SetUint64(cfg.chainID), cfg.coordinatorAddr)
	response := result.Attestation(deadline)
	digest := domain.Digest(response)

	signature, err := signer.Sign(digest, cfg.privateKey)
	if err != nil {
		return attestationReport{}, fmt.Errorf("signing attestation: %w", err)
	}

	calldata, err := cfg.contract.Pack(
		"fulfillCompute",
		result.RequestID,
		result.ModelID,
		result.OutputHash,
		deadline,
		signature,
	)
	if err != nil {
		return attestationReport{}, fmt.Errorf("encoding calldata: %w", err)
	}

	return attestationReport{
		Mode:        "dry-run",
		Signer:      crypto.PubkeyToAddress(cfg.privateKey.PublicKey).Hex(),
		ChainID:     cfg.chainID,
		Coordinator: cfg.coordinatorAddr.Hex(),
		RequestID:   result.RequestID.Uint64(),
		ModelID:     hex.EncodeToString(result.ModelID[:]),
		InputHash:   result.InputHash.Hex(),
		OutputHash:  result.OutputHash.Hex(),
		Output:      json.RawMessage(result.Output),
		Deadline:    deadline.Uint64(),
		Digest:      digest.Hex(),
		Signature:   "0x" + hex.EncodeToString(signature),
		Calldata:    "0x" + hex.EncodeToString(calldata),
	}, nil
}

func runListener(ctx context.Context, cfg config) error {
	client, err := ethclient.DialContext(ctx, cfg.rpcURL)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", cfg.rpcURL, err)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("reading chain id: %w", err)
	}
	if chainID.Uint64() != cfg.chainID {
		return fmt.Errorf("node reports chain id %s, but --chain-id is %d", chainID, cfg.chainID)
	}

	code, err := client.CodeAt(ctx, cfg.coordinatorAddr, nil)
	if err != nil {
		return fmt.Errorf("reading coordinator code: %w", err)
	}
	if len(code) == 0 {
		return fmt.Errorf("no contract deployed at %s", cfg.coordinatorAddr)
	}

	workerAddress := crypto.PubkeyToAddress(cfg.privateKey.PublicKey)
	active, err := workerStatus(ctx, client, cfg, workerAddress)
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("worker %s is not registered or not active", workerAddress)
	}
	log.Printf("worker %s listening on %s (coordinator %s)", workerAddress.Hex(), cfg.rpcURL, cfg.coordinatorAddr.Hex())

	return pollRequests(ctx, client, cfg, workerAddress)
}

func workerStatus(ctx context.Context, client *ethclient.Client, cfg config, worker common.Address) (bool, error) {
	callData, err := cfg.contract.Pack("isActiveWorker", worker)
	if err != nil {
		return false, fmt.Errorf("encoding isActiveWorker call: %w", err)
	}
	output, err := client.CallContract(ctx, ethereum.CallMsg{To: &cfg.coordinatorAddr, Data: callData}, nil)
	if err != nil {
		return false, fmt.Errorf("calling isActiveWorker: %w", err)
	}
	values, err := cfg.contract.Unpack("isActiveWorker", output)
	if err != nil {
		return false, fmt.Errorf("decoding isActiveWorker: %w", err)
	}
	if len(values) != 1 {
		return false, fmt.Errorf("unexpected isActiveWorker return arity %d", len(values))
	}
	active, ok := values[0].(bool)
	if !ok {
		return false, errors.New("unexpected isActiveWorker return type")
	}
	return active, nil
}

func pollRequests(ctx context.Context, client *ethclient.Client, cfg config, worker common.Address) error {
	nextBlock := uint64(0)
	if cfg.fromBlock < 0 {
		head, err := client.BlockNumber(ctx)
		if err != nil {
			return fmt.Errorf("reading head: %w", err)
		}
		nextBlock = head + 1
	} else {
		nextBlock = uint64(cfg.fromBlock)
	}
	seen := make(map[uint64]struct{})
	requestTopic := cfg.contract.Events["ComputeRequested"].ID
	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown requested; worker stopped")
			return nil
		case <-ticker.C:
		}

		latest, err := client.BlockNumber(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("reading head: %v", err)
			continue
		}
		if latest < nextBlock {
			continue
		}

		query := ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(nextBlock),
			ToBlock:   new(big.Int).SetUint64(latest),
			Addresses: []common.Address{cfg.coordinatorAddr},
			Topics:    [][]common.Hash{{requestTopic}},
		}
		logs, err := client.FilterLogs(ctx, query)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("filtering logs: %v", err)
			continue
		}
		nextBlock = latest + 1

		for _, entry := range logs {
			event, err := decodeComputeRequested(cfg.contract, entry)
			if err != nil {
				log.Printf("decoding event at block %d: %v", entry.BlockNumber, err)
				continue
			}
			requestID := event.RequestID.Uint64()
			if _, done := seen[requestID]; done {
				continue
			}
			seen[requestID] = struct{}{}

			if err := fulfillRequest(ctx, client, cfg, worker, event); err != nil {
				log.Printf("request %d: %v", requestID, err)
			}
		}
	}
}

func decodeComputeRequested(contract abi.ABI, log types.Log) (computeRequestedEvent, error) {
	definition, ok := contract.Events["ComputeRequested"]
	if !ok {
		return computeRequestedEvent{}, errors.New("ComputeRequested event missing from ABI")
	}

	indexed := make(abi.Arguments, 0, len(definition.Inputs))
	for _, input := range definition.Inputs {
		if input.Indexed {
			indexed = append(indexed, input)
		}
	}
	values := make(map[string]interface{}, len(definition.Inputs))
	if err := abi.ParseTopicsIntoMap(values, indexed, log.Topics[1:]); err != nil {
		return computeRequestedEvent{}, fmt.Errorf("decoding indexed fields: %w", err)
	}
	if err := contract.UnpackIntoMap(values, "ComputeRequested", log.Data); err != nil {
		return computeRequestedEvent{}, fmt.Errorf("decoding event data: %w", err)
	}

	requestID, ok := values["requestId"].(*big.Int)
	if !ok {
		return computeRequestedEvent{}, errors.New("unexpected requestId type")
	}
	requester, ok := values["requester"].(common.Address)
	if !ok {
		return computeRequestedEvent{}, errors.New("unexpected requester type")
	}
	modelID, ok := values["modelId"].([32]byte)
	if !ok {
		return computeRequestedEvent{}, errors.New("unexpected modelId type")
	}
	inputData, ok := values["inputData"].([]byte)
	if !ok {
		return computeRequestedEvent{}, errors.New("unexpected inputData type")
	}

	return computeRequestedEvent{
		RequestID: requestID,
		Requester: requester,
		ModelID:   modelID,
		InputData: inputData,
	}, nil
}

func fulfillRequest(ctx context.Context, client *ethclient.Client, cfg config, worker common.Address, event computeRequestedEvent) error {
	fulfilled, err := requestFulfilled(ctx, client, cfg, event.RequestID)
	if err != nil {
		return err
	}
	if fulfilled {
		return nil
	}

	executor := engine.DeterministicExecutor{}
	result, err := executor.Execute(ctx, engine.Request{
		RequestID: event.RequestID,
		ModelID:   event.ModelID,
		Input:     event.InputData,
	})
	if err != nil {
		return fmt.Errorf("executing: %w", err)
	}

	deadline := new(big.Int).SetInt64(time.Now().Add(cfg.attestationTTL).Unix())
	domain := signer.NewDomain(new(big.Int).SetUint64(cfg.chainID), cfg.coordinatorAddr)
	digest := domain.Digest(result.Attestation(deadline))
	signature, err := signer.Sign(digest, cfg.privateKey)
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	calldata, err := cfg.contract.Pack(
		"fulfillCompute",
		result.RequestID,
		result.ModelID,
		result.OutputHash,
		deadline,
		signature,
	)
	if err != nil {
		return fmt.Errorf("encoding calldata: %w", err)
	}

	nonce, err := client.PendingNonceAt(ctx, worker)
	if err != nil {
		return fmt.Errorf("reading nonce: %w", err)
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("suggesting gas price: %w", err)
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("reading chain id: %w", err)
	}

	gasLimit := uint64(400_000)
	if estimate, estimateErr := client.EstimateGas(ctx, ethereum.CallMsg{
		From: worker, To: &cfg.coordinatorAddr, Data: calldata,
	}); estimateErr == nil {
		gasLimit = estimate + estimate/5
	}

	tx := types.NewTransaction(nonce, cfg.coordinatorAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), cfg.privateKey)
	if err != nil {
		return fmt.Errorf("signing transaction: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return fmt.Errorf("sending transaction: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, signed)
	if err != nil {
		return fmt.Errorf("waiting for receipt %s: %w", signed.Hash(), err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("transaction %s reverted", signed.Hash())
	}

	log.Printf(
		"fulfilled request=%s model=%x digest=%s output=%s tx=%s",
		event.RequestID, event.ModelID, digest.Hex(), result.OutputHash.Hex(), signed.Hash(),
	)
	return nil
}

func requestFulfilled(ctx context.Context, client *ethclient.Client, cfg config, requestID *big.Int) (bool, error) {
	callData, err := cfg.contract.Pack("getRequest", requestID)
	if err != nil {
		return false, fmt.Errorf("encoding getRequest: %w", err)
	}
	output, err := client.CallContract(ctx, ethereum.CallMsg{To: &cfg.coordinatorAddr, Data: callData}, nil)
	if err != nil {
		return false, fmt.Errorf("calling getRequest: %w", err)
	}
	values, err := cfg.contract.Unpack("getRequest", output)
	if err != nil {
		return false, fmt.Errorf("decoding getRequest: %w", err)
	}
	if len(values) != 7 {
		return false, fmt.Errorf("unexpected getRequest return arity %d", len(values))
	}
	fulfilled, ok := values[6].(bool)
	if !ok {
		return false, errors.New("unexpected getRequest return type")
	}
	return fulfilled, nil
}

func parseBytes32(value string) ([32]byte, error) {
	var out [32]byte
	trimmed := strings.TrimPrefix(value, "0x")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, fmt.Errorf("not hex: %w", err)
	}
	if len(decoded) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}
