package siws

import (
	"fmt"
	"math/big"
)

// alphabet is the Bitcoin/Solana base58 alphabet.
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// maxBase58Len bounds DecodeBase58 input. Base58 → base256 conversion is O(n²),
// so an unbounded input is a CPU-DoS vector. A 32-byte Solana key encodes to at
// most 44 chars; 128 is a generous cap that keeps the decoder constant-bounded.
const maxBase58Len = 128

var (
	bigZero     = big.NewInt(0)
	bigBase     = big.NewInt(58)
	alphabetIdx [128]int8 // rune -> index; -1 means not in alphabet
)

func init() {
	for i := range alphabetIdx {
		alphabetIdx[i] = -1
	}
	for i, c := range alphabet {
		alphabetIdx[c] = int8(i)
	}
}

// DecodeBase58 decodes a base58-encoded string into bytes.
// Returns ErrMalformed (wrapped) if any character is outside the alphabet.
func DecodeBase58(s string) ([]byte, error) {
	if len(s) > maxBase58Len {
		return nil, fmt.Errorf("base58: input too long: %w", ErrMalformed)
	}
	n := new(big.Int)
	for _, r := range s {
		if r > 127 || alphabetIdx[r] < 0 {
			return nil, fmt.Errorf("base58: invalid character: %w", ErrMalformed)
		}
		n.Mul(n, bigBase)
		n.Add(n, big.NewInt(int64(alphabetIdx[r])))
	}

	decoded := n.Bytes()

	// Preserve leading zeros (encoded as '1' characters).
	nLeadingZeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		nLeadingZeros++
	}
	if nLeadingZeros > 0 {
		out := make([]byte, nLeadingZeros+len(decoded))
		copy(out[nLeadingZeros:], decoded)
		return out, nil
	}
	return decoded, nil
}

// EncodeBase58 encodes bytes into a base58 string.
func EncodeBase58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var result []byte
	mod := new(big.Int)
	for n.Cmp(bigZero) > 0 {
		n.DivMod(n, bigBase, mod)
		result = append(result, alphabet[mod.Int64()])
	}
	// Leading zero bytes encode as '1'.
	for _, byt := range b {
		if byt != 0 {
			break
		}
		result = append(result, '1')
	}
	// Reverse.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}
