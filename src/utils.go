package snarkpack

import (
	"math/big"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// Returns a vector of scalar powers a^0 to a^(n-1)
func Powers(a *big.Int, n int) []*big.Int {
	result := make([]*big.Int, n)
	result[0] = big.NewInt(1)
	for i := 0; i < n; i++ {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(a, result[i-1]), bn254.ID.ScalarField())
	}
	return result
}