package main

import (
	"encoding/hex"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	proofHex = "00888fc931fd91022d6a9209924ee22de263759d648449fd596be44cb006581504936131a12761c3fe278fb002d591e1dfb0a8cca2977789805507591bdf6719177a4b371aa0cdc6eda92fe210b42af7c9ae46d75658822ed9f3afdc52cce2c21e7bb588d2526dada97c2de8bd19929e3f3d3a75248f8db306eb30fb31d5a7d50f5ead31948af1b56cd28a8b0fce6c77e54f7ab5872b30be877eeae147a8ab7f11b48b52c2a3ec4c953db3dd8538482cf5567caba59a1b9e2eaedf164a7f926c17ee66c09804f75ecd743b46ce9d8b52390aae114c8c8fbbfc8ecdf2e0b3717a1834e3cb75c684a21f292bea13f19886d44dc0db588bc8d456dce7b956e51249000000012d8cb9d272e9e9239debedfd50ada261df764338ace3d991513689305a3d6c401d1f2bab59611e6b5fe29bdbfb98125dfe429e58928439418d1b8217349333f90bae2b9af68b6f570f738f824b18b33bb5ede2dcf2d727c066036156b383304f2f65aab7c0060d8ef9ee2e16d9b1f9a2ba2581aecdcd38d0c66ef4f1ba18a41f"
	inputHex = "00000000000000000000000000000000000000000000000000000000000000ac00000000000000000000000000000000000000000000000000000000000000c300000000000000000000000000000000000000000000000000000000000000e700000000000000000000000000000000000000000000000000000000000000f800000000000000000000000000000000000000000000000000000000000000b20000000000000000000000000000000000000000000000000000000000000017000000000000000000000000000000000000000000000000000000000000008700000000000000000000000000000000000000000000000000000000000000a700000000000000000000000000000000000000000000000000000000000000c2000000000000000000000000000000000000000000000000000000000000004900000000000000000000000000000000000000000000000000000000000000fd000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000d0000000000000000000000000000000000000000000000000000000000000000d00000000000000000000000000000000000000000000000000000000000000e2000000000000000000000000000000000000000000000000000000000000005b000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000008d000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000097000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000f600000000000000000000000000000000000000000000000000000000000000d9000000000000000000000000000000000000000000000000000000000000004700000000000000000000000000000000000000000000000000000000000000c20000000000000000000000000000000000000000000000000000000000000039000000000000000000000000000000000000000000000000000000000000002e000000000000000000000000000000000000000000000000000000000000009c000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000f8"
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
	println("len(proofBytes): ", len(proofBytes))
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
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
		print("input[", i, "]: ", hex.EncodeToString(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)]), ", ")
	}

	// solidity contract inputs
	var proof [8]*big.Int

	// proof.Ar, proof.Bs, proof.Krs
	// 32*8 = 256 bytes
	for i := 0; i < 8; i++ {
		proof[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}

	// 4 bytes
	// prepare commitments for calling
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(c.Int64())

	if commitmentCount != 1 {
		panic("commitmentCount != .NbCommitments")
	}

	// 32*4 = 128 bytes
	var commitments [2]*big.Int
	var commitmentPok [2]*big.Int

	// commitments
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

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

