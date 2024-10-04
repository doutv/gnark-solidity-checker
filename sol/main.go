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
	proofHex = "163cc1f0805d9226ebc76d38f4dbefb4afb03b3d2b022f5064bd380dc239d0bc201cc888f6ee7296e46f9419dbbc715441af5ab20c432bfc0a25d10a41a7d80f0824ae6cede313a218df767fad9df03eacfa2e1978e7e0bdbfc664f05a711b8e1a44c3989ff2cb0c351b155154ccdd88d0f9fc31c1a4965ce80f5b9eed5204a80e526c0922692dd93977c416dfa15116c48a6df484dbb99e4ad822f4202651bd173930e6307287230468428e6b0c022d074b825012126ffca995763b83abc86015aec3f7b18904d1049e5fcfddaa248b672072c8cfd9420856d781e32d4fda9a267870a34b8b53faaa842632dfeb74aeb21bae6dc21cccbe76dddc807f8c1bd5000000010ae3d6e7e8b6751fbdbb5cc7b6dcb55c95122b64158d9e56b7320e682bd3a204075a2f01e66238ddd5612f11b235c2b75b126e82f8790f3ccf9629a2fc2c1fe60fda980dd210ba3a97700ec4f62622fbb2cbd55f548300220df974c10216e8210692cdc744aab533231ec3990f51a2f893c78b08542a48223537d30d956b2c00"
	inputHex = "00000000000000000000000000000000000000000000000000000000000000fb"
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

