// Package signer implements the EIP-712 typed-data hashing and secp256k1 signing scheme used by
// VerifiableComputeCoordinator.
//
// The Solidity contract hashes:
//
//	domainSeparator = keccak256(abi.encode(
//	    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
//	    keccak256("InfernetVerifiableOracle"),
//	    keccak256("1"),
//	    chainId,
//	    verifyingContract))
//
//	structHash = keccak256(abi.encode(
//	    keccak256("ComputeResponse(uint256 requestId,bytes32 modelId,bytes32 outputHash,uint256 deadline)"),
//	    requestId, modelId, outputHash, deadline))
//
//	digest = keccak256(0x1901 || domainSeparator || structHash)
//
// This package reproduces that byte-for-byte so a Go worker's signature is accepted on-chain.
package signer

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// DomainName is the EIP-712 domain name configured in the coordinator constructor.
	DomainName = "InfernetVerifiableOracle"
	// DomainVersion is the EIP-712 domain version configured in the coordinator constructor.
	DomainVersion = "1"
)

// ErrInvalidSignature is returned when a signature cannot be parsed into a public key.
var ErrInvalidSignature = errors.New("invalid signature")

var (
	domainTypeHash = crypto.Keccak256Hash(
		[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
	)
	responseTypeHash = crypto.Keccak256Hash(
		[]byte("ComputeResponse(uint256 requestId,bytes32 modelId,bytes32 outputHash,uint256 deadline)"),
	)
	nameHash    = crypto.Keccak256Hash([]byte(DomainName))
	versionHash = crypto.Keccak256Hash([]byte(DomainVersion))

	domainArguments = mustArguments("bytes32", "bytes32", "bytes32", "uint256", "address")
	structArguments = mustArguments("bytes32", "uint256", "bytes32", "bytes32", "uint256")
)

func mustArguments(types ...string) abi.Arguments {
	arguments := make(abi.Arguments, 0, len(types))
	for _, typeName := range types {
		typ, err := abi.NewType(typeName, "", nil)
		if err != nil {
			panic(fmt.Sprintf("signer: invalid ABI type %q: %v", typeName, err))
		}
		arguments = append(arguments, abi.Argument{Type: typ})
	}
	return arguments
}

// Domain is the EIP-712 domain of a coordinator deployment.
type Domain struct {
	Name              string
	Version           string
	ChainID           *big.Int
	VerifyingContract common.Address
}

// NewDomain returns the domain used by a coordinator at verifyingContract on chainID.
func NewDomain(chainID *big.Int, verifyingContract common.Address) Domain {
	return Domain{
		Name:              DomainName,
		Version:           DomainVersion,
		ChainID:           new(big.Int).Set(chainID),
		VerifyingContract: verifyingContract,
	}
}

// ComputeResponse is the worker attestation struct.
type ComputeResponse struct {
	RequestID  *big.Int
	ModelID    [32]byte
	OutputHash [32]byte
	Deadline   *big.Int
}

// TypeHash returns the EIP-712 type hash of the ComputeResponse struct.
func TypeHash() common.Hash { return responseTypeHash }

// Separator returns the EIP-712 domain separator.
func (d Domain) Separator() common.Hash {
	if d.ChainID == nil {
		panic("signer: domain chain ID must not be nil")
	}
	encoded, err := domainArguments.Pack(
		domainTypeHash,
		nameHash,
		versionHash,
		d.ChainID,
		d.VerifyingContract,
	)
	if err != nil {
		panic(fmt.Sprintf("signer: encoding domain separator: %v", err))
	}
	return crypto.Keccak256Hash(encoded)
}

// HashStruct returns the hash of the ComputeResponse fields.
func (r ComputeResponse) HashStruct() common.Hash {
	requestID := r.RequestID
	if requestID == nil {
		requestID = new(big.Int)
	}
	deadline := r.Deadline
	if deadline == nil {
		deadline = new(big.Int)
	}
	encoded, err := structArguments.Pack(
		responseTypeHash,
		requestID,
		r.ModelID,
		r.OutputHash,
		deadline,
	)
	if err != nil {
		panic(fmt.Sprintf("signer: encoding compute response: %v", err))
	}
	return crypto.Keccak256Hash(encoded)
}

// Digest returns the EIP-712 digest that the worker signs.
func (d Domain) Digest(response ComputeResponse) common.Hash {
	separator := d.Separator()
	structHash := response.HashStruct()
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, separator[:], structHash[:])
}

// Sign produces a 65-byte (r, s, v) signature over the digest, with v in {27, 28} so that the
// EVM ecrecover precompile used by OpenZeppelin's ECDSA.recover accepts it.
func Sign(digest common.Hash, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	signature, err := crypto.Sign(digest[:], privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing digest: %w", err)
	}
	signature[64] += 27
	return signature, nil
}

// Recover returns the address that produced signature over digest.
func Recover(digest common.Hash, signature []byte) (common.Address, error) {
	if len(signature) != crypto.SignatureLength {
		return common.Address{}, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, crypto.SignatureLength, len(signature))
	}
	normalized := make([]byte, crypto.SignatureLength)
	copy(normalized, signature)
	if normalized[64] >= 27 {
		normalized[64] -= 27
	}
	publicKey, err := crypto.SigToPub(digest[:], normalized)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return crypto.PubkeyToAddress(*publicKey), nil
}
