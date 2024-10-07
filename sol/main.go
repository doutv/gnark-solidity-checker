package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	proofHex = "271fdea6a9653d30bdd77830ace7323a92c18618b8fccd6f49dc86e6a16a343026d8965e0b879d219b459ffd9006aab38d7cd23a5a004776bc67c7ec1b17246614b5d5981a0314871836e123ed129fcbb964e3c7d8a0ee21b008c0fa195a3eb503bf604d55e55c122a49b38e74a95b8eeacbc8ece7137b3f74e4aebf6b21ecac1b984df1de542be834bb54c055406158570c20ce34cf4c95c7e9ad7b0a6033f124dd1b66e1829a63f5eb7c03553dcf9a8af405d1dbc8218c9694d02e5ef586a11ed9730bc03b3217a6eafe47efb323cccac67d6f034e9ac649e21d667aee06b72049e88127eca7f6143f56f74dd59ddb5a6c2b1be125bd6262895ebeb1d10a1000000001125c778dc3df6b76acdf23debb606c97aa0d9ece6567a83bbe709d11b993a68c1b707f8c096f2e362a84c2f5a9997133dca1a4aecccd3bff96d2bac710cd65b6131bf13d331a2448948cedf737a049d24c489b54aeb44d0131e6023219f8fe9f09b87cfadc6d0b3d4913f6c6f7cac3bdf311de8c70f742d006b7b1998f7d37dd"
	inputHex = "00000000000000000000000000000000000000000000000000000000000000670000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003d00000000000000000000000000000000000000000000000000000000000000be000000000000000000000000000000000000000000000000000000000000009500000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000e7000000000000000000000000000000000000000000000000000000000000003e00000000000000000000000000000000000000000000000000000000000000bb00000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000000000000000000000000000000000000000008200000000000000000000000000000000000000000000000000000000000000be000000000000000000000000000000000000000000000000000000000000004f00000000000000000000000000000000000000000000000000000000000000cc0000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000007500000000000000000000000000000000000000000000000000000000000000a800000000000000000000000000000000000000000000000000000000000000ee00000000000000000000000000000000000000000000000000000000000000ba000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000c10000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000001500000000000000000000000000000000000000000000000000000000000000d700000000000000000000000000000000000000000000000000000000000000fc000000000000000000000000000000000000000000000000000000000000006b000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000004900000000000000000000000000000000000000000000000000000000000000bb00000000000000000000000000000000000000000000000000000000000000f500000000000000000000000000000000000000000000000000000000000000de0000000000000000000000000000000000000000000000000000000000000061"
	nbPublicInputs = 32
	fpSize = 4 * 8
)

func main() {
	const gasLimit uint64 = 4712388

	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	checkErr(err, "init keyed transactor")

	genesis := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 Eth
	}
	backend := backends.NewSimulatedBackend(genesis, gasLimit)

	// deploy verifier contract
	_, _, verifierContract, err := DeployVerifier(auth, backend)
	checkErr(err, "deploy verifier contract failed")
	backend.Commit()


	proofBytes, err := hex.DecodeString(proofHex)
	checkErr(err, "decode proof hex failed")

	

	inputBytes, err := hex.DecodeString(inputHex)
	checkErr(err, "decode input hex failed")

	if len(inputBytes)%fr.Bytes != 0 {
		panic("inputBytes mod fr.Bytes !=0")
	}

	// convert public inputs
	nbInputs := len(inputBytes) / fr.Bytes
	if nbInputs != nbPublicInputs {
		panic("nbInputs != nbPublicInputs")
	}
	var input [nbPublicInputs]*big.Int
	println("publicInput:")
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
		fmt.Printf("0x%32X\n", inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
	}

	// solidity contract inputs
	var proof [8]*big.Int

	// proof.Ar, proof.Bs, proof.Krs
	println("proof:")
	for i := 0; i < 8; i++ {
		proof[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
		fmt.Printf("0x%32X\n", proofBytes[fpSize*i : fpSize*(i+1)])
	}


	// prepare commitments for calling
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(c.Int64())

	if commitmentCount != 1 {
		panic("commitmentCount != .NbCommitments")
	}

	var commitments [2]*big.Int
	var commitmentPok [2]*big.Int

	// commitments
	println("commitments:")
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
		fmt.Printf("0x%32X\n", proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])
	println("commitmentPok:")
	fmt.Printf("0x%32X\n", proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	fmt.Printf("0x%32X\n", proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	// call the contract
	err = verifierContract.VerifyProof(&bind.CallOpts{}, proof, commitments, commitmentPok, input)
	checkErr(err, "calling verifier on chain gave error")

	// compress proof
	compressed, err := verifierContract.CompressProof(&bind.CallOpts{}, proof, commitments, commitmentPok)
	checkErr(err, "compressing proof gave error")

	// verify compressed proof
	err = verifierContract.VerifyCompressedProof(&bind.CallOpts{}, compressed.Compressed, compressed.CompressedCommitments, compressed.CompressedCommitmentPok, input)
	checkErr(err, "calling verifier with compressed proof on chain gave error")
	
}

func checkErr(err error, ctx string) {
	if err != nil {
		panic(ctx + " " + err.Error())
	}
}

