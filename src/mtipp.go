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
	_, _, G, H := bn254.Generators()
	v1 := bn254.BatchScalarMultiplicationG2(&H, aVec[:n])
	v2 := bn254.BatchScalarMultiplicationG2(&H, bVec[:n])
	w1 := bn254.BatchScalarMultiplicationG1(&G, aVec[n:])
	w2 := bn254.BatchScalarMultiplicationG1(&G, bVec[n:])

	return MTIPP_SRS{
		vkey: VKey{v1, v2},
		wkey: WKey{w1, w2},
		kzg:  *kzgSRS,
	}
}

func Prove(srs MTIPP_SRS, h_com *big.Int, tab, uab, tc, uc, zab bn254.GT, zc bn254.G1Affine , r *big.Int, A []bn254.G1Affine, B []bn254.G2Affine, C []bn254.G1Affine) {
	// Prepare vectors @Step 3
	n0 := len(srs.vkey.V1)
	rPowers := Powers(r, n0)
	rInverses := Inverses(rPowers)

	// Step-7, hashCom is computed once
	hcom := hashCom([4]bn254.GT{tab, uab, tc, uc})
	// Step-8 compute x_0
	x := hashX0([2]*big.Int{r, hcom}, zab, zc)

	// Split and collapse
	// Vectors of left and right commitments for AB and C
	tablVector := make([]bn254.GT, n0)
	uablVector := make([]bn254.GT, n0)
	tabrVector := make([]bn254.GT, n0)
	uabrVector := make([]bn254.GT, n0)
	tclVector := make([]bn254.GT, n0)
	uclVector := make([]bn254.GT, n0)
	tcrVector := make([]bn254.GT, n0)
	ucrVector := make([]bn254.GT, n0)

	// Initialize vectors
	a := A
	b := B
	c := C
	v1 := srs.vkey.V1
	v2 := srs.vkey.V2
	w1 := srs.wkey.W1
	w2 := srs.wkey.W2

	for nPrime := n0 / 2; nPrime > 1; nPrime = nPrime / 2 {
		// Step-3
		bPrime := ScaleG2(b, rPowers)
		w1Prime := ScaleG1(w1, rInverses)
		w2Prime := ScaleG1(w2, rInverses)

		// Step-4
		zabl := Pair(A[nPrime:], bPrime[:nPrime])
		zabr := Pair(A[:nPrime], bPrime[nPrime:])
		zcl := MultiExpG1(C[nPrime:], rPowers[:nPrime])
		zcr := MultiExpG1(C[:nPrime], rPowers[nPrime:])

		// Step-5 Compute left cross commitments
		tabl, uabl := CommitDouble(VKey{v1[nPrime:], v2[nPrime:]}, WKey{w1Prime[:nPrime], w2Prime[:nPrime]}, a[nPrime:], bPrime[:nPrime])
		tcl, ucl := CommitSingle(VKey{v1[nPrime:], v2[nPrime:]}, c[nPrime:])
		tablVector = append(tablVector, tabl)
		uablVector = append(uablVector, uabl)
		tclVector = append(tclVector, tcl)
		uclVector = append(uclVector, ucl)

		// Step-6 Compute right cross commitments
		tabr, uabr := CommitDouble(VKey{v1[:nPrime], v2[:nPrime]}, WKey{w1Prime[nPrime:], w2Prime[nPrime:]}, a[:nPrime], bPrime[nPrime:])
		tcr, ucr := CommitSingle(VKey{v1[:nPrime], v2[:nPrime]}, c[:nPrime])
		tabrVector = append(tabrVector, tabr)
		uabrVector = append(uabrVector, uabr)
		tcrVector = append(tcrVector, tcr)
		ucrVector = append(ucrVector, ucr)

		// TODO: continue here from step-8 to compute x_i
		// Another mistake in the paper, the definition of hash expects 12 elements of GT however, zcl, zcr are G1
		x = hash(x, [12]bn254.GT{zabl, zabr, zcl, zcr, tabl, uabl, tabr, uabr, tcl, ucl, tcr, ucr})

	}
}
