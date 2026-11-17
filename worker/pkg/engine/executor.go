// Package engine contains the off-chain execution pipeline that turns a compute request into a
// deterministic, hashable inference result.
package engine

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/arturochs13-boop/infernet-verifiable-oracle/worker/pkg/signer"
)

// ModelVersion identifies the deterministic scoring model implemented by DeterministicExecutor.
const ModelVersion = "deterministic-scoring-v1"

// ErrEmptyInput is returned when a request carries no input payload.
var ErrEmptyInput = errors.New("engine: empty input")

// Request is a compute request observed on-chain or supplied on the command line.
type Request struct {
	RequestID *big.Int
	ModelID   [32]byte
	Input     []byte
}

// Result is the executor output together with the commitments the worker signs.
type Result struct {
	RequestID  *big.Int
	ModelID    [32]byte
	InputHash  common.Hash
	OutputHash common.Hash
	Output     []byte
}

// Attestation builds the EIP-712 response commitment for this result.
func (r Result) Attestation(deadline *big.Int) signer.ComputeResponse {
	return signer.ComputeResponse{
		RequestID:  r.RequestID,
		ModelID:    r.ModelID,
		OutputHash: [32]byte(r.OutputHash),
		Deadline:   deadline,
	}
}

// Executor runs a model over the request input. Implementations must be deterministic for a given
// input so independent workers can reproduce the output hash.
type Executor interface {
	Execute(ctx context.Context, request Request) (Result, error)
}

// DeterministicExecutor classifies text into negative, neutral, or positive using a stable score
// derived from the keccak256 digest of the input. It is not a trained model; it is a deterministic
// stand-in whose value is that every honest worker computes the same output and hash, which is what
// the on-chain attestation binds.
type DeterministicExecutor struct{}

// ScoringOutput is the JSON document the executor produces.
type ScoringOutput struct {
	Version   string `json:"version"`
	ModelID   string `json:"model_id"`
	InputHash string `json:"input_hash"`
	Score     uint32 `json:"score"`
	Label     string `json:"label"`
}

// Execute runs the deterministic scoring model.
//
// The score is the big-endian value of the first eight bytes of keccak256(input) reduced into
// [0, 10000] basis points. Labels are assigned at 5000 and 8000 basis points. The output document is
// serialized with fixed field order and hex-encoded hashes, so the output hash is stable across Go
// versions and platforms.
func (DeterministicExecutor) Execute(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("executing request: %w", err)
	}
	if len(request.Input) == 0 {
		return Result{}, ErrEmptyInput
	}
	if request.ModelID == ([32]byte{}) {
		return Result{}, errors.New("engine: zero model id")
	}

	inputHash := crypto.Keccak256Hash(request.Input)
	score := scoreFromHash(inputHash)
	output := ScoringOutput{
		Version:   ModelVersion,
		ModelID:   hex.EncodeToString(request.ModelID[:]),
		InputHash: inputHash.Hex(),
		Score:     score,
		Label:     labelFor(score),
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return Result{}, fmt.Errorf("encoding model output: %w", err)
	}

	return Result{
		RequestID:  copyBigInt(request.RequestID),
		ModelID:    request.ModelID,
		InputHash:  inputHash,
		OutputHash: crypto.Keccak256Hash(encoded),
		Output:     encoded,
	}, nil
}

func scoreFromHash(hash [32]byte) uint32 {
	value := binary.BigEndian.Uint64(hash[:8])
	return uint32(value % 10001)
}

func labelFor(score uint32) string {
	switch {
	case score >= 8000:
		return "positive"
	case score >= 5000:
		return "neutral"
	default:
		return "negative"
	}
}

func copyBigInt(value *big.Int) *big.Int {
	if value == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(value)
}
