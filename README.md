# gnark-solidity-checker

`gnark-solidity-checker generate` is a helper to compile gnark solidity verification circuits using `solc`,
generate go bindings using `abigen` and submit a proof running on geth simulated backend using `gnark-solidity-checker verify`.

## Install dependencies

### Install Solidity

`brew install solidity`
or

```bash
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```

### Install Go

`brew install golang`

### Install `abigen`

`go install github.com/ethereum/go-ethereum/cmd/abigen@v1.12.0`

## Usage
```bash
go run main.go generate --dir sol --solidity p256-1Verifier.sol

go run main.go verify --dir sol --groth16 -n 1 --commitment 1 --public-inputs 00000000000000000000000000000000000000000000000000000000000000fb --proof 163cc1f0805d9226ebc76d38f4dbefb4afb03b3d2b022f5064bd380dc239d0bc201cc888f6ee7296e46f9419dbbc715441af5ab20c432bfc0a25d10a41a7d80f0824ae6cede313a218df767fad9df03eacfa2e1978e7e0bdbfc664f05a711b8e1a44c3989ff2cb0c351b155154ccdd88d0f9fc31c1a4965ce80f5b9eed5204a80e526c0922692dd93977c416dfa15116c48a6df484dbb99e4ad822f4202651bd173930e6307287230468428e6b0c022d074b825012126ffca995763b83abc86015aec3f7b18904d1049e5fcfddaa248b672072c8cfd9420856d781e32d4fda9a267870a34b8b53faaa842632dfeb74aeb21bae6dc21cccbe76dddc807f8c1bd5000000010ae3d6e7e8b6751fbdbb5cc7b6dcb55c95122b64158d9e56b7320e682bd3a204075a2f01e66238ddd5612f11b235c2b75b126e82f8790f3ccf9629a2fc2c1fe60fda980dd210ba3a97700ec4f62622fbb2cbd55f548300220df974c10216e8210692cdc744aab533231ec3990f51a2f893c78b08542a48223537d30d956b2c00
```