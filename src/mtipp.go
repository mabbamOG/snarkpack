package snarkpack

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)


func Setup(n int, a, b *big.Int) MTIPP_SRS {
	kzgSRS, _ := kzg.NewSRS(uint64(n), a)

	aVec := Powers(a, 2*n)
	bVec := Powers(b, 2*n)
	_, _, G, H :=bn254.Generators()

	v1 := make([]bn254.G2Affine, n)
	v2 := make([]bn254.G2Affine, n)
	w1 := make([]bn254.G1Affine, n)
	w2 := make([]bn254.G1Affine, n)

	for i:=0; i< n; i++ {
		v1[i] = *(new(bn254.G2Affine).ScalarMultiplication(&H, aVec[i]))
		v2[i] = *(new(bn254.G2Affine).ScalarMultiplication(&H, bVec[i]))
		w1[i] = *(new(bn254.G1Affine).ScalarMultiplication(&G, aVec[i+n]))
		w2[i] = *(new(bn254.G1Affine).ScalarMultiplication(&G, bVec[i+n]))
	}

	return MTIPP_SRS{
		cs: CS{V1: v1, V2: v2},
		cd: CD{V1: v1, V2: v2, W1: w1, W2: w2},
		kzg: *kzgSRS,
	}
}