package engine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func modelID() [32]byte {
	return [32]byte(common.HexToHash("0xbb90cdb04ca02199f9d23b4e77f96238eea6d61fa0bc900568885e13b5af55fe"))
}

func request(input string) Request {
	return Request{RequestID: big.NewInt(1), ModelID: modelID(), Input: []byte(input)}
}

func TestExecuteIsDeterministic(t *testing.T) {
	executor := DeterministicExecutor{}
	first, err := executor.Execute(context.Background(), request("classify the protocol"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	for i := 0; i < 100; i++ {
		next, err := executor.Execute(context.Background(), request("classify the protocol"))
		if err != nil {
			t.Fatalf("execute iteration %d: %v", i, err)
		}
		if next.OutputHash != first.OutputHash {
			t.Fatalf("output hash changed on iteration %d", i)
		}
		if string(next.Output) != string(first.Output) {
			t.Fatalf("output document changed on iteration %d", i)
		}
	}
}

func TestExecuteBindsInputAndOutput(t *testing.T) {
	executor := DeterministicExecutor{}
	first, err := executor.Execute(context.Background(), request("alpha"))
	if err != nil {
		t.Fatalf("execute alpha: %v", err)
	}
	second, err := executor.Execute(context.Background(), request("beta"))
	if err != nil {
		t.Fatalf("execute beta: %v", err)
	}

	if first.InputHash != crypto.Keccak256Hash([]byte("alpha")) {
		t.Fatal("input hash is not keccak256(input)")
	}
	if first.InputHash == second.InputHash {
		t.Fatal("different inputs produced the same input hash")
	}
	if first.OutputHash == second.OutputHash {
		t.Fatal("different inputs produced the same output hash")
	}
	if first.OutputHash != crypto.Keccak256Hash(first.Output) {
		t.Fatal("output hash is not keccak256(output)")
	}
}

func TestExecuteOutputDocument(t *testing.T) {
	result, err := (DeterministicExecutor{}).Execute(context.Background(), request("hello"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var document ScoringOutput
	if err := json.Unmarshal(result.Output, &document); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if document.Version != ModelVersion {
		t.Fatalf("version = %q, want %q", document.Version, ModelVersion)
	}
	if document.Score > 10000 {
		t.Fatalf("score %d out of range", document.Score)
	}
	if document.Label != labelFor(document.Score) {
		t.Fatalf("label %q does not match score %d", document.Label, document.Score)
	}
	if document.InputHash != result.InputHash.Hex() {
		t.Fatalf("document input hash %q != %q", document.InputHash, result.InputHash.Hex())
	}
	if document.ModelID != hex.EncodeToString(result.ModelID[:]) {
		t.Fatalf("document model id %q does not match %x", document.ModelID, result.ModelID)
	}
}

func TestLabels(t *testing.T) {
	cases := []struct {
		score uint32
		want  string
	}{
		{0, "negative"},
		{4999, "negative"},
		{5000, "neutral"},
		{7999, "neutral"},
		{8000, "positive"},
		{10000, "positive"},
	}
	for _, testCase := range cases {
		if got := labelFor(testCase.score); got != testCase.want {
			t.Fatalf("labelFor(%d) = %q, want %q", testCase.score, got, testCase.want)
		}
	}
}

func TestExecuteRejectsInvalidRequests(t *testing.T) {
	executor := DeterministicExecutor{}

	if _, err := executor.Execute(context.Background(), Request{RequestID: big.NewInt(1), ModelID: modelID()}); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("empty input: got %v, want ErrEmptyInput", err)
	}
	if _, err := executor.Execute(context.Background(), Request{RequestID: big.NewInt(1), Input: []byte("x")}); err == nil {
		t.Fatal("accepted a zero model id")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executor.Execute(cancelled, request("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: got %v, want context.Canceled", err)
	}
}

func TestAttestationCopiesResultFields(t *testing.T) {
	result, err := (DeterministicExecutor{}).Execute(context.Background(), request("attest me"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	deadline := big.NewInt(1_800_000_000)
	attestation := result.Attestation(deadline)

	if attestation.RequestID.Cmp(result.RequestID) != 0 {
		t.Fatal("request id not carried into the attestation")
	}
	if attestation.OutputHash != result.OutputHash {
		t.Fatal("output hash not carried into the attestation")
	}
	if attestation.ModelID != result.ModelID {
		t.Fatal("model id not carried into the attestation")
	}
	if attestation.Deadline.Cmp(deadline) != 0 {
		t.Fatal("deadline not carried into the attestation")
	}
}
