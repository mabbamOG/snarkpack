package snarkpack

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
)

type VKey struct {
	V1 []bn254.G2Affine
	V2 []bn254.G2Affine
}

type WKey struct {
	W1 []bn254.G1Affine
	W2 []bn254.G1Affine
}


type MTIPP_SRS struct {
	vkey VKey
	wkey WKey
	kzg kzg.SRS
}

type Z struct {
	AB_L bn254.GT
	AB_R bn254.GT
	C_L  bn254.G1Affine
	C_R  bn254.G1Affine
}


type MTIPP_Witness struct {
	A []bn254.G1Affine
	B []bn254.G2Affine
	C []bn254.G1Affine
}