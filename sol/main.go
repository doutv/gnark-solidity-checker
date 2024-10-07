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
	proofHex = "0eb92045fde9c3170cca6f6cd06b22c13ac0312c13b78e88d8a7e0ba9d7e6eca1bcc830249611e4aa65e7669c87d79b0042810e20beb6354d1b4d46e02841d302b6f2ef2017109df10a255a043e26dba99592aa165eb3a8ee26fd4758c4437c12fcddedb242562b961a05863a07883f4110d4eab703976220b3de8bc216a77a12f84e70f9224819e85944256d025fb48b7050183c352b60fb39dd458ba32d43220015003dd59e20592e6d93f14c9a7e87ba027f223c0a4bfa5e3d0babc8f88ea284c6493bd9443afe045a5508b80e47147c82dc2d9fc04d590eb74fe3a5db5e8122221a5041a5497695b594ed0c34706d37faac2034b37c6e301212c7b312dc4000000010c832c534d1bd3a5a9559db1169638788ec892ffc217df49d3c2fefba98e6676274a18e703de630563aadc1b90df7967ea492857eef2ced4b91edab614cef9e61844777acdcdcd7d9646492f395e7de7752403a8f017f988dca9aff41beda22c254d96dc20ee821a48c5ea595427d0fa63939780e75aefd87cf1228c1088b16c"
	inputHex = "00da5d4804cca342e3fe52a9d1b4103f5ac52170662ab20fb18bedf1cac2c111"
	nbPublicInputs = 1
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

