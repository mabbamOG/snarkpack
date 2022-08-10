package snarkpack

import (
	"crypto/sha512"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)
func hashCom(gt *[4]bn254.GT) *big.Int {
	var bytes []byte
	for _, element := range gt {
		bytes = append(bytes, element.Marshal()...)
	}
	return hashToFr(bytes)
}

func hashX0(z *[2]big.Int, gt *bn254.GT, g1 *bn254.G1Affine) *big.Int {
	var bytes []byte
	bytes = append(bytes, z[0].Bytes()...)
	bytes = append(bytes, z[1].Bytes()...)
	bytes = append(bytes, gt.Marshal()...)
	bytes = append(bytes, g1.Marshal()...)
	return hashToFr(bytes)
}

func hash(z *big.Int, gt *[12]bn254.GT) *big.Int {
	var bytes []byte
	bytes = append(bytes, z.Bytes()...)
	for _, element := range gt {
		bytes = append(bytes, element.Marshal()...)
	}
	return hashToFr(bytes)
}

func hashZ(z *big.Int, g2 *[2]bn254.G2Affine, g1 *[2]bn254.G1Affine) *big.Int {
	var bytes []byte
	bytes = append(bytes, z.Bytes()...)
	bytes = append(bytes, g2[0].Marshal()...)
	bytes = append(bytes, g1[1].Marshal()...)
	bytes = append(bytes, g1[0].Marshal()...)
	bytes = append(bytes, g1[1].Marshal()...)
	return hashToFr(bytes)
}

func hashToFr(bytes []byte) *big.Int {
	hash := sha512.New()
	hash.Write(bytes)
	sum := hash.Sum(nil)
	value := new(big.Int).SetBytes(sum)
	value = value.Mod(value, bn254.ID.ScalarField())
	return value
}
