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

### Install `gnark-solidity-checker`

`go install`

## Demo

```bash
cd sol
# Print proof, publicInput, commitments in uint256 solidity format
go run main.go gnark_solidity.go
```

## Usage
```bash
# 1. Copy the .sol verifier contract generated by Gnark to sol/

# 2. Generate combined.json and go bindings
gnark-solidity-checker generate --dir sol --solidity p256-1Verifier.sol

# 3. Generate main.go and call the verifier contract
gnark-solidity-checker verify --dir sol --groth16 --commitment 1 --dir sol --nb-public-inputs 1 --proof 0eb92045fde9c3170cca6f6cd06b22c13ac0312c13b78e88d8a7e0ba9d7e6eca1bcc830249611e4aa65e7669c87d79b0042810e20beb6354d1b4d46e02841d302b6f2ef2017109df10a255a043e26dba99592aa165eb3a8ee26fd4758c4437c12fcddedb242562b961a05863a07883f4110d4eab703976220b3de8bc216a77a12f84e70f9224819e85944256d025fb48b7050183c352b60fb39dd458ba32d43220015003dd59e20592e6d93f14c9a7e87ba027f223c0a4bfa5e3d0babc8f88ea284c6493bd9443afe045a5508b80e47147c82dc2d9fc04d590eb74fe3a5db5e8122221a5041a5497695b594ed0c34706d37faac2034b37c6e301212c7b312dc4000000010c832c534d1bd3a5a9559db1169638788ec892ffc217df49d3c2fefba98e6676274a18e703de630563aadc1b90df7967ea492857eef2ced4b91edab614cef9e61844777acdcdcd7d9646492f395e7de7752403a8f017f988dca9aff41beda22c254d96dc20ee821a48c5ea595427d0fa63939780e75aefd87cf1228c1088b16c --public-inputs 00da5d4804cca342e3fe52a9d1b4103f5ac52170662ab20fb18bedf1cac2c111
```