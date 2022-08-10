package snarkpack

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)

type CS struct {
	V1 []bn254.G2Affine
	V2 []bn254.G2Affine
}

type CD struct {
	V1 []bn254.G2Affine
	V2 []bn254.G2Affine
	W1 []bn254.G1Affine
	W2 []bn254.G1Affine
}

type Commitment struct {
	T bn254.GT
	U bn254.GT
}

type MTIPP_SRS struct {
	cs  CS
	cd  CD
	kzg kzg.SRS
}

type MTIPP_Statement struct {
	cm_AB Commitment
	cm_C  Commitment
	Z_AB  bn254.GT
	Z_C   bn254.GT
	r     big.Int
}

type MTIPP_Witness struct {
	A []bn254.G1Affine
	B []bn254.G2Affine
	C []bn254.G1Affine
}
