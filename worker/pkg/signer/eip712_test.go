package signer

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The Solidity suite test_CrossLanguageDigestVector deploys the coordinator at
// 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f on chain 31337 and prints this digest for the
// response below. Both suites pin the same constant, so either hash implementation drifting fails a
// build.
const (
	vectorVerifyingContract = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f"
	vectorModelID           = "0xbb90cdb04ca02199f9d23b4e77f96238eea6d61fa0bc900568885e13b5af55fe"
	vectorOutputHash        = "0x3be2ba19dcc77e90b23fc96a514c329f5976d5a6c3b152bbb87a893b519a6f10"
	vectorDigest            = "0x149d20553bdfaf696c71f873fee78a15c3118f0a0efc3611b32c99b4456ac2b7"
)

func testDomain() Domain {
	return NewDomain(big.NewInt(31337), common.HexToAddress(vectorVerifyingContract))
}

func testResponse() ComputeResponse {
	return ComputeResponse{
		RequestID:  big.NewInt(1),
		ModelID:    [32]byte(common.HexToHash(vectorModelID)),
		OutputHash: [32]byte(common.HexToHash(vectorOutputHash)),
		Deadline:   big.NewInt(1_800_000_000),
	}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", 0xA11CE))
	if err != nil {
		t.Fatalf("deriving test key: %v", err)
	}
	return key
}

func TestDigestMatchesSolidityVector(t *testing.T) {
	digest := testDomain().Digest(testResponse())
	if got, want := digest.Hex(), vectorDigest; got != want {
		t.Fatalf("digest mismatch with Solidity vector\n got: %s\nwant: %s", got, want)
	}
}

func TestDigestIsDeterministic(t *testing.T) {
	domain := testDomain()
	first := domain.Digest(testResponse())
	for i := 0; i < 50; i++ {
		if next := domain.Digest(testResponse()); next != first {
			t.Fatalf("digest changed on iteration %d: %s != %s", i, next.Hex(), first.Hex())
		}
	}
}

func TestSeparatorBindsChainAndContract(t *testing.T) {
	base := testDomain().Separator()
	otherChain := NewDomain(big.NewInt(1), common.HexToAddress(vectorVerifyingContract)).Separator()
	otherContract := NewDomain(big.NewInt(31337), common.HexToAddress("0x000000000000000000000000000000000000dEaD")).Separator()

	if base == otherChain {
		t.Fatal("separator ignored the chain id")
	}
	if base == otherContract {
		t.Fatal("separator ignored the verifying contract")
	}
}

func TestStructHashBindsEveryField(t *testing.T) {
	response := testResponse()
	base := response.HashStruct()

	mutate := []struct {
		name   string
		change func(*ComputeResponse)
	}{
		{"request", func(r *ComputeResponse) { r.RequestID = big.NewInt(2) }},
		{"model", func(r *ComputeResponse) { r.ModelID[31] ^= 0xff }},
		{"output", func(r *ComputeResponse) { r.OutputHash[0] ^= 0xff }},
		{"deadline", func(r *ComputeResponse) { r.Deadline = big.NewInt(1_800_000_001) }},
	}

	for _, testCase := range mutate {
		changed := response
		testCase.change(&changed)
		if changed.HashStruct() == base {
			t.Fatalf("%s field is not covered by the struct hash", testCase.name)
		}
	}
}

func TestSignAndRecover(t *testing.T) {
	key := testKey(t)
	domain := testDomain()
	digest := domain.Digest(testResponse())

	signature, err := Sign(digest, key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if len(signature) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(signature))
	}
	if v := signature[64]; v != 27 && v != 28 {
		t.Fatalf("expected recovery id 27 or 28, got %d", v)
	}

	recovered, err := Recover(digest, signature)
	if err != nil {
		t.Fatalf("recovering: %v", err)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey); recovered != want {
		t.Fatalf("recovered %s, want %s", recovered, want)
	}
}

func TestRecoverRejectsTampering(t *testing.T) {
	key := testKey(t)
	digest := testDomain().Digest(testResponse())
	signature, err := Sign(digest, key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	expected := crypto.PubkeyToAddress(key.PublicKey)

	tamperedDigest := digest
	tamperedDigest[0] ^= 0x01
	recovered, err := Recover(tamperedDigest, signature)
	if err == nil && recovered == expected {
		t.Fatal("tampered digest recovered the original signer")
	}

	tamperedSignature := bytes.Clone(signature)
	tamperedSignature[10] ^= 0xff
	if recovered, err := Recover(digest, tamperedSignature); err == nil && recovered == expected {
		t.Fatal("tampered signature recovered the original signer")
	}
}

func TestRecoverRejectsMalformedLengths(t *testing.T) {
	digest := testDomain().Digest(testResponse())
	for _, length := range []int{0, 64, 66} {
		signature := make([]byte, length)
		if _, err := Recover(digest, signature); err == nil {
			t.Fatalf("accepted a %d-byte signature", length)
		}
	}
}

func TestDigestMatchesEthereumTypedDataPrelude(t *testing.T) {
	domain := testDomain()
	response := testResponse()
	separator := domain.Separator()
	structHash := response.HashStruct()

	manual := crypto.Keccak256Hash([]byte{0x19, 0x01}, separator[:], structHash[:])
	if digest := domain.Digest(response); digest != manual {
		t.Fatalf("digest %s does not match manual 0x1901 construction %s", digest, manual)
	}
}

func TestNilDeadlineIsEncodedAsZero(t *testing.T) {
	domain := testDomain()
	withNil := ComputeResponse{RequestID: big.NewInt(7), Deadline: nil}
	withZero := ComputeResponse{RequestID: big.NewInt(7), Deadline: big.NewInt(0)}
	if withNil.HashStruct() != withZero.HashStruct() {
		t.Fatal("nil deadline must encode as zero")
	}
	if domain.Digest(withNil) == domain.Digest(testResponse()) {
		t.Fatal("different responses produced the same digest")
	}
}
