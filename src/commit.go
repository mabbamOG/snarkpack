package snarkpack

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func CommitSingle(vkey VKey, A []bn254.G1Affine) (t bn254.GT, u bn254.GT) {
	t = Pair(A, vkey.V1)
	u = Pair(A, vkey.V2)
	return t, u
}

func CommitDouble(vkey VKey, wkey WKey, A []bn254.G1Affine, B []bn254.G2Affine) (t bn254.GT, u bn254.GT) {
	AV1 := Pair(A, vkey.V1)
	W1B := Pair(wkey.W1, B)
	t = *new(bn254.GT).Add(&AV1, &W1B)

	AV2 := Pair(A, vkey.V2)
	W2B := Pair(wkey.W2, B)
	u = *new(bn254.GT).Add(&AV2, &W2B)
	return t, u
}
