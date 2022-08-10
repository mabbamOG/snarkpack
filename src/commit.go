package snarkpack

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
)
// Commit single
func (cs CS) Commit(A []bn254.G1Affine) Commitment {
	//TODO: check equal length of inputs
	t, err := bn254.Pair(A, cs.V1)
	if err != nil {
		panic(err)
	}

	u, err := bn254.Pair(A, cs.V2)
	if err != nil {
		panic(err)
	}

	return Commitment{T: t, U: u}
}

// Commit double
func (cd CD) Commit(A []bn254.G1Affine, B []bn254.G2Affine) Commitment {
	//TODO: check equal length of inputs
	AW1 := append(A, cd.W1...)
	V1B := append(cd.V1, B...)
	t, err := bn254.Pair(AW1, V1B)
	if err != nil {
		panic(err)
	}
	
	AW2 := append(A, cd.W2...)
	V2B := append(cd.V2, B...)
	u, err := bn254.Pair(AW2, V2B)
	if err != nil {
		panic(err)
	}

	return Commitment{T: t, U: u}
}
