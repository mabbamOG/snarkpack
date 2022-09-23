package snarkpack

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Returns a vector of scalar powers a^0 to a^(n-1)
func Powers(a *big.Int, n int) []fr.Element {
	resElements := make([]fr.Element, n)
	base := new(fr.Element).SetBigInt(a)
	resElements[0] = fr.NewElement(1)
	for i := 0; i < n; i++ {
		resElements[i] = *new(fr.Element).Mul(&resElements[i-1], base)
	}
	return resElements
}

// Returns inverses of the input vector [a_0^{-1}, ... a_{n-1}^{-1}]
func Inverses(a []fr.Element) []fr.Element {
	n := len(a)
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		a[i].Inverse(&result[i])
	}
	return result
}

// Returns a vector of G1 points [A_1^{a_1}, ..., A_{n-1}^{a_{n-1}}]
func ScaleG1(A []bn254.G1Affine, a []fr.Element) []bn254.G1Affine {
	n := len(A)
	var tmp *big.Int
	result := make([]bn254.G1Affine, n)
	for i:=0; i<n; i++ {
		a[i].ToBigIntRegular(tmp)
		result[i] = *new(bn254.G1Affine).ScalarMultiplication(&A[i], tmp)
	}
	return result
}

// Returns a vector of G2 points [A_1^{a_1}, ..., A_{n-1}^{a_{n-1}}]
func ScaleG2(A []bn254.G2Affine, a []fr.Element) []bn254.G2Affine {
	n := len(A)
	var tmp *big.Int
	result := make([]bn254.G2Affine, n)
	for i:=0; i<n; i++ {
		a[i].ToBigIntRegular(tmp)
		result[i] = *new(bn254.G2Affine).ScalarMultiplication(&A[i], tmp)
	}
	return result
}

// Returns MultiExponentiation of A*a in G1
func MultiExpG1(A []bn254.G1Affine, a []fr.Element) bn254.G1Affine {
	result, err := new(bn254.G1Affine).MultiExp(A, a,  ecc.MultiExpConfig{NbTasks: 128})
	if err != nil {
		panic(err)
	}
	return *result
}

// Returns MultiExponentiation of A*a in G2
func MultiExpG2(A []bn254.G2Affine, a []fr.Element) bn254.G2Affine {
	result, err := new(bn254.G2Affine).MultiExp(A, a,  ecc.MultiExpConfig{NbTasks: 128})
	if err != nil {
		panic(err)
	}
	return *result
}

func HadamardProduct(A1 []bn254.G1Affine, A2 []bn254.G1Affine) []bn254.G1Affine {
	n := len(A1)
	result := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		result[i] = *new(bn254.G1Affine).Add(&A1[i], &A2[i])
	}
	return result
}

func Pair(A []bn254.G1Affine, B []bn254.G2Affine) bn254.GT {
	result, err := bn254.Pair(A, B)
	if err != nil {
		panic(err)
	}
	return result
}