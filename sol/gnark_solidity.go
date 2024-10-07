// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package main

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// VerifierMetaData contains all meta data concerning the Verifier contract.
var VerifierMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"CommitmentInvalid\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ProofInvalid\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"PublicInputNotInField\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint256[8]\",\"name\":\"proof\",\"type\":\"uint256[8]\"},{\"internalType\":\"uint256[2]\",\"name\":\"commitments\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"commitmentPok\",\"type\":\"uint256[2]\"}],\"name\":\"compressProof\",\"outputs\":[{\"internalType\":\"uint256[4]\",\"name\":\"compressed\",\"type\":\"uint256[4]\"},{\"internalType\":\"uint256[1]\",\"name\":\"compressedCommitments\",\"type\":\"uint256[1]\"},{\"internalType\":\"uint256\",\"name\":\"compressedCommitmentPok\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256[4]\",\"name\":\"compressedProof\",\"type\":\"uint256[4]\"},{\"internalType\":\"uint256[1]\",\"name\":\"compressedCommitments\",\"type\":\"uint256[1]\"},{\"internalType\":\"uint256\",\"name\":\"compressedCommitmentPok\",\"type\":\"uint256\"},{\"internalType\":\"uint256[1]\",\"name\":\"input\",\"type\":\"uint256[1]\"}],\"name\":\"verifyCompressedProof\",\"outputs\":[],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256[8]\",\"name\":\"proof\",\"type\":\"uint256[8]\"},{\"internalType\":\"uint256[2]\",\"name\":\"commitments\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"commitmentPok\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[1]\",\"name\":\"input\",\"type\":\"uint256[1]\"}],\"name\":\"verifyProof\",\"outputs\":[],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Bin: "0x6080604052348015600f57600080fd5b50612bd18061001f6000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063317297ea1461004657806343db3c7214610062578063b1c3a00e1461007e575b600080fd5b610060600480360381019061005b91906126b6565b6100b0565b005b61007c60048036038101906100779190612761565b610a8a565b005b610098600480360381019061009391906127cc565b610fa3565b6040516100a793929190612960565b60405180910390f35b6100b86125a9565b6100c06125cb565b6100c86125ed565b6100e9866000600181106100df576100de612997565b5b60200201356111a5565b836000600281106100fd576100fc612997565b5b602002018460016002811061011557610114612997565b5b602002018281525082815250505060008061012f876111a5565b9150915060607f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000018560006002811061016a57610169612997565b5b60200201518660016002811061018357610182612997565b5b60200201518360405160200161019b93929190612a9f565b6040516020818303038152906040528051906020012060001c6101be9190612b07565b866000600181106101d2576101d1612997565b5b602002018181525050846000600281106101ef576101ee612997565b5b60200201518460006018811061020857610207612997565b5b6020020181815250508460016002811061022557610224612997565b5b60200201518460016018811061023e5761023d612997565b5b6020020181815250507f2a9d326372325d469d9519208566f6c5a2909fbcdaaeda50299e2d5a9515e43d8460026018811061027c5761027b612997565b5b6020020181815250507f0d78257100b22c38271010a9c0ff75473c68dd1c9907e7f982758e0c0ef9c419846003601881106102ba576102b9612997565b5b6020020181815250507f19334ff1b1fd5f5c911870466ad1c1752f55f76c41d41d2cccd99b6e54637f3b846004601881106102f8576102f7612997565b5b6020020181815250507f02a636ac8b87597ce31a5bed4eb9fe4f47ea7bd24f06990b6a1a23051be666618460056018811061033657610335612997565b5b602002018181525050828460066018811061035457610353612997565b5b602002018181525050818460076018811061037257610371612997565b5b6020020181815250507f236b031381bfcc973088c6287b0a1850d4e172519424020b31aa0bb7cf443b50846008601881106103b0576103af612997565b5b6020020181815250507f03c23c837b581c33999b1e7bca0c2b1032be5cb246dce51f7e6245eac0800c04846009601881106103ee576103ed612997565b5b6020020181815250507f06c310618936ac799ff5186c5fbb2804f48e4a2d7e49d072ca56029a02151f4b84600a6018811061042c5761042b612997565b5b6020020181815250507f2f10621636482ae38639a09e72ac26832e5c2e4777b2ad45d1436c9a673f1e5384600b6018811061046a57610469612997565b5b60200201818152505060006040516020816101808860085afa915080518216915050806104c3576040517fa3a93fee00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b505050506000806104eb896000600481106104e1576104e0612997565b5b60200201356111a5565b9150915060008060008061052f8d60026004811061050c5761050b612997565b5b60200201358e60016004811061052557610524612997565b5b60200201356112de565b935093509350935060008061055b8f60036004811061055157610550612997565b5b60200201356111a5565b9150915060008061056d8e8e8e6116c4565b91509150898b60006018811061058657610585612997565b5b602002018181525050888b6001601881106105a4576105a3612997565b5b602002018181525050868b6002601881106105c2576105c1612997565b5b602002018181525050878b6003601881106105e0576105df612997565b5b602002018181525050848b6004601881106105fe576105fd612997565b5b602002018181525050858b60056018811061061c5761061b612997565b5b602002018181525050838b60066018811061063a57610639612997565b5b602002018181525050828b60076018811061065857610657612997565b5b6020020181815250507f10ad5d5aaf76e38267139cef742a876e9b32813d8db86ad6614db969b3d71af28b60086018811061069657610695612997565b5b6020020181815250507f1682660e4a43aa963f064d9a641f320e30b8898047b958328e325e9a3d11560c8b6009601881106106d4576106d3612997565b5b6020020181815250507f28b75855fa53ba8bd03557f9da79834a9397b49a67beac9e4b56ad595ff8f1fd8b600a6018811061071257610711612997565b5b6020020181815250507f074d847bbd04d767e47ecca58332bbc21438ef0303b33ffeeaa05d301df233978b600b601881106107505761074f612997565b5b6020020181815250507f1b59230740b5f2bd5e54ee56939b42cb58fc6fbaa7a253c3f8e9a91c4a57e9828b600c6018811061078e5761078d612997565b5b6020020181815250507f2b1e80dfe8806d9b79f01d68a277fda7aa3968a4742532e5cb92b184c3bc04a38b600d601881106107cc576107cb612997565b5b6020020181815250507f0c5747f4dd1d9c809db3b8914fe738213ffaec816ac38369251147fb0399fa338b600e6018811061080a57610809612997565b5b6020020181815250507f08785258863bcdc1ccb370b2f2f55fb99ef4271fa837136daee0a04774a7ceca8b600f6018811061084857610847612997565b5b6020020181815250507f161c3625934d4e862384b48564042bffc278ec785fec196ea8cbe411e096c46b8b60106018811061088657610885612997565b5b6020020181815250507f02033793fc3ea57444f913996a034cc9bb9ad7f56a300d507dbc254d66ab10738b6011601881106108c4576108c3612997565b5b602002018181525050818b6012601881106108e2576108e1612997565b5b602002018181525050808b601360188110610900576108ff612997565b5b6020020181815250507f1fc1aaf1f0c9e390cd38a92ecdb81bc4bd5ded458726e248f980e9d193af2d7a8b60146018811061093e5761093d612997565b5b6020020181815250507f17953f1e4181427e9c398464ae3d9057c3298e982cdcb1c6b811def066b8227e8b60156018811061097c5761097b612997565b5b6020020181815250507f207a52acb6995ebf43f5aef541a43eacaa763ecaa5d559ffe5b310fe2b3f32e48b6016601881106109ba576109b9612997565b5b6020020181815250507f103707596b47016a9ef3314b593ad89e5c2f8be60ecae6f05505a994b91f86098b6017601881106109f8576109f7612997565b5b6020020181815250506000610a0b6125a9565b6020816103008f60085afa9150811580610a3e5750600181600060018110610a3657610a35612997565b5b602002015114155b15610a75576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b50505050505050505050505050505050505050565b610a926125a9565b60607f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000185600060028110610ac957610ac8612997565b5b602002013586600160028110610ae257610ae1612997565b5b602002013583604051602001610afa93929190612a9f565b6040516020818303038152906040528051906020012060001c610b1d9190612b07565b82600060018110610b3157610b30612997565b5b602002018181525050600060405160408782377f2a9d326372325d469d9519208566f6c5a2909fbcdaaeda50299e2d5a9515e43d60408201527f0d78257100b22c38271010a9c0ff75473c68dd1c9907e7f982758e0c0ef9c41960608201527f19334ff1b1fd5f5c911870466ad1c1752f55f76c41d41d2cccd99b6e54637f3b60808201527f02a636ac8b87597ce31a5bed4eb9fe4f47ea7bd24f06990b6a1a23051be6666160a082015260408660c08301377f236b031381bfcc973088c6287b0a1850d4e172519424020b31aa0bb7cf443b506101008201527f03c23c837b581c33999b1e7bca0c2b1032be5cb246dce51f7e6245eac0800c046101208201527f06c310618936ac799ff5186c5fbb2804f48e4a2d7e49d072ca56029a02151f4b6101408201527f2f10621636482ae38639a09e72ac26832e5c2e4777b2ad45d1436c9a673f1e536101608201526020816101808360085afa91508051821691505080610ccb576040517fa3a93fee00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b600080610d1086868a6002806020026040519081016040528092919082600260200280828437600081840152601f19601f8201169050808301925050505050506116c4565b915091506040516101008a82377f10ad5d5aaf76e38267139cef742a876e9b32813d8db86ad6614db969b3d71af26101008201527f1682660e4a43aa963f064d9a641f320e30b8898047b958328e325e9a3d11560c6101208201527f28b75855fa53ba8bd03557f9da79834a9397b49a67beac9e4b56ad595ff8f1fd6101408201527f074d847bbd04d767e47ecca58332bbc21438ef0303b33ffeeaa05d301df233976101608201527f1b59230740b5f2bd5e54ee56939b42cb58fc6fbaa7a253c3f8e9a91c4a57e9826101808201527f2b1e80dfe8806d9b79f01d68a277fda7aa3968a4742532e5cb92b184c3bc04a36101a08201527f0c5747f4dd1d9c809db3b8914fe738213ffaec816ac38369251147fb0399fa336101c08201527f08785258863bcdc1ccb370b2f2f55fb99ef4271fa837136daee0a04774a7ceca6101e08201527f161c3625934d4e862384b48564042bffc278ec785fec196ea8cbe411e096c46b6102008201527f02033793fc3ea57444f913996a034cc9bb9ad7f56a300d507dbc254d66ab107361022082015282610240820152816102608201527f1fc1aaf1f0c9e390cd38a92ecdb81bc4bd5ded458726e248f980e9d193af2d7a6102808201527f17953f1e4181427e9c398464ae3d9057c3298e982cdcb1c6b811def066b8227e6102a08201527f207a52acb6995ebf43f5aef541a43eacaa763ecaa5d559ffe5b310fe2b3f32e46102c08201527f103707596b47016a9ef3314b593ad89e5c2f8be60ecae6f05505a994b91f86096102e08201526020816103008360085afa93508051841693505082610f98576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b505050505050505050565b610fab612610565b610fb36125a9565b6000610fef86600060088110610fcc57610fcb612997565b5b602002013587600160088110610fe557610fe4612997565b5b6020020135611877565b8360006004811061100357611002612997565b5b6020020181815250506110788660036008811061102357611022612997565b5b60200201358760026008811061103c5761103b612997565b5b60200201358860056008811061105557611054612997565b5b60200201358960046008811061106e5761106d612997565b5b6020020135611a2b565b8460026004811061108c5761108b612997565b5b60200201856001600481106110a4576110a3612997565b5b60200201828152508281525050506110ec866006600881106110c9576110c8612997565b5b6020020135876007600881106110e2576110e1612997565b5b6020020135611877565b83600360048110611100576110ff612997565b5b602002018181525050611143856000600281106111205761111f612997565b5b60200201358660016002811061113957611138612997565b5b6020020135611877565b8260006001811061115757611156612997565b5b60200201818152505061119a8460006002811061117757611176612997565b5b6020020135856001600281106111905761118f612997565b5b6020020135611877565b905093509350939050565b600080600083036111bc57600080915091506112d9565b60006001808516149050600184901c92507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478310611226576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6112c37f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061125857611257612ad8565b5b60037f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061128957611288612ad8565b5b867f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806112b9576112b8612ad8565b5b8889090908612002565b915080156112d7576112d48261209f565b91505b505b915091565b6000806000806000861480156112f45750600085145b1561130c5760008060008093509350935093506116bb565b6000600180881614905060006002808916149050600288901c95508694507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478610158061137957507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478510155b156113b0576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b60007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806113e1576113e0612ad8565b5b60037f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4761140e9190612b67565b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061143d5761143c612ad8565b5b888a0909905060007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061147457611473612ad8565b5b887f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806114a4576114a3612ad8565b5b8a8b0909905060007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806114db576114da612ad8565b5b887f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061150b5761150a612ad8565b5b8a8b090990507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806115405761153f612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061156f5761156e612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061159e5761159d612ad8565b5b8a860984087f2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e50896506116837f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806115f9576115f8612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061162857611627612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061165757611656612ad8565b5b8c870984087f2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e7750861209f565b955061169087878661210b565b809750819850505084156116b5576116a78761209f565b96506116b28661209f565b95505b50505050505b92959194509250565b6000806000600190506040516040810160007f2ea046bf9554144e79326d4b18f0850e73f4a5acf606a4828e6515cfd6812ccd83527f1766b6362a25bc8163cc8d101457cc3e212c1fcef39aef5f3a3c7c3547c7a2556020840152865182526020870151602083015260408360808560065afa841693506000825260006020830152883590508060408301527f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000181108416935060408260608460075afa8416935060408360808560065afa841693507f1e92d7fa21e915c60c72a9e320347af3d8829934e6ec790b18747d61006bb6ed82527f2c0d59065f41697480bc5631389cda84c0656be8b10c695b96d4dddac43744bd6020830152875190508060408301527f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000181108416935060408260608460075afa8416935060408360808560065afa8416935082519550602083015194505050508061186e576040517fa54f8e2700000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b50935093915050565b60007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47831015806118c857507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478210155b156118ff576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b60008314801561190f5750600082145b1561191d5760009050611a25565b60006119bc7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061195157611950612ad8565b5b60037f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061198257611981612ad8565b5b877f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806119b2576119b1612ad8565b5b898a090908612002565b90508083036119d5576000600185901b17915050611a25565b6119de8161209f565b83036119f35760018085901b17915050611a25565b6040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b92915050565b6000807f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4786101580611a7d57507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478510155b80611aa857507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478410155b80611ad357507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478310155b15611b0a576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b60008385878917171703611b245760008091509150611ff9565b60008060007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611b5857611b57612ad8565b5b60037f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47611b859190612b67565b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611bb457611bb3612ad8565b5b8a8c0909905060007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611beb57611bea612ad8565b5b8a7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611c1b57611c1a612ad8565b5b8c8d0909905060007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611c5257611c51612ad8565b5b8a7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611c8257611c81612ad8565b5b8c8d090990507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611cb757611cb6612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611ce657611ce5612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611d1557611d14612ad8565b5b8c860984087f2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5089450611dfa7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611d7057611d6f612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611d9f57611d9e612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611dce57611dcd612ad8565b5b8e870984087f2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e7750861209f565b9350505050600080611e9e7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611e3457611e33612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611e6357611e62612ad8565b5b8586097f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611e9557611e94612ad8565b5b87880908612002565b9050611f2b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611ed257611ed1612ad8565b5b7f183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea47f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4780611f2257611f21612ad8565b5b84880809612408565b15915050611f3a83838361210b565b80935081945050508287148015611f5057508186145b15611f7a57600081611f63576000611f66565b60025b60ff1660028b901b17179450879350611ff5565b611f838361209f565b87148015611f985750611f958261209f565b86145b15611fc257600181611fab576000611fae565b60025b60ff1660028b901b17179450879350611ff4565b6040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5b5050505b94509492505050565b600061202e827f0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52612473565b9050817f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806120605761205f612ad8565b5b8283091461209a576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b919050565b60007f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478083816120d2576120d1612ad8565b5b067f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47038161210357612102612ad8565b5b069050919050565b60008060006121ac7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061214257612141612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061217157612170612ad8565b5b8788097f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806121a3576121a2612ad8565b5b898a0908612002565b905083156121c0576121bd8161209f565b90505b61224b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806121f2576121f1612ad8565b5b7f183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea47f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061224257612241612ad8565b5b848a0809612002565b92507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061227c5761227b612ad8565b5b6122b77f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806122ae576122ad612ad8565b5b6002860961250b565b860991507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806122ea576122e9612ad8565b5b6123247f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061231c5761231b612ad8565b5b84850961209f565b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061235357612352612ad8565b5b85860908861415806123c857507f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061238f5761238e612ad8565b5b7f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47806123be576123bd612ad8565b5b8385096002098514155b156123ff576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b50935093915050565b600080612435837f0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52612473565b9050827f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061246757612466612ad8565b5b82830914915050919050565b60008060405160208152602080820152602060408201528460608201528360808201527f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4760a082015260208160c08360055afa9150805192505080612504576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5092915050565b6000612537827f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45612473565b905060017f30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd478061256a57612569612ad8565b5b828409146125a4576040517f7fcdd1f400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b919050565b6040518060200160405280600190602082028036833780820191505090505090565b6040518060400160405280600290602082028036833780820191505090505090565b604051806103000160405280601890602082028036833780820191505090505090565b6040518060800160405280600490602082028036833780820191505090505090565b600080fd5b600080fd5b60008190508260206004028201111561265857612657612637565b5b92915050565b60008190508260206001028201111561267a57612679612637565b5b92915050565b6000819050919050565b61269381612680565b811461269e57600080fd5b50565b6000813590506126b08161268a565b92915050565b60008060008060e085870312156126d0576126cf612632565b5b60006126de8782880161263c565b94505060806126ef8782880161265e565b93505060a0612700878288016126a1565b92505060c06127118782880161265e565b91505092959194509250565b60008190508260206008028201111561273957612738612637565b5b92915050565b60008190508260206002028201111561275b5761275a612637565b5b92915050565b6000806000806101a0858703121561277c5761277b612632565b5b600061278a8782880161271d565b94505061010061279c8782880161273f565b9350506101406127ae8782880161273f565b9250506101806127c08782880161265e565b91505092959194509250565b600080600061018084860312156127e6576127e5612632565b5b60006127f48682870161271d565b9350506101006128068682870161273f565b9250506101406128188682870161273f565b9150509250925092565b600060049050919050565b600081905092915050565b6000819050919050565b61284b81612680565b82525050565b600061285d8383612842565b60208301905092915050565b6000602082019050919050565b61287f81612822565b612889818461282d565b925061289482612838565b8060005b838110156128c55781516128ac8782612851565b96506128b783612869565b925050600181019050612898565b505050505050565b600060019050919050565b600081905092915050565b6000819050919050565b6000602082019050919050565b612903816128cd565b61290d81846128d8565b9250612918826128e3565b8060005b838110156129495781516129308782612851565b965061293b836128ed565b92505060018101905061291c565b505050505050565b61295a81612680565b82525050565b600060c0820190506129756000830186612876565b61298260808301856128fa565b61298f60a0830184612951565b949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b6000819050919050565b6129e16129dc82612680565b6129c6565b82525050565b600081519050919050565b600081905092915050565b6000819050602082019050919050565b612a1681612680565b82525050565b6000612a288383612a0d565b60208301905092915050565b6000602082019050919050565b6000612a4c826129e7565b612a5681856129f2565b9350612a61836129fd565b8060005b83811015612a92578151612a798882612a1c565b9750612a8483612a34565b925050600181019050612a65565b5085935050505092915050565b6000612aab82866129d0565b602082019150612abb82856129d0565b602082019150612acb8284612a41565b9150819050949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b6000612b1282612680565b9150612b1d83612680565b925082612b2d57612b2c612ad8565b5b828206905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000612b7282612680565b9150612b7d83612680565b9250828203905081811115612b9557612b94612b38565b5b9291505056fea264697066735822122012a87bdabc2f7c5b39998282592f915fea7156a3e98efb773e45ce5c98f37fcc64736f6c63430008190033",
}

// VerifierABI is the input ABI used to generate the binding from.
// Deprecated: Use VerifierMetaData.ABI instead.
var VerifierABI = VerifierMetaData.ABI

// VerifierBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use VerifierMetaData.Bin instead.
var VerifierBin = VerifierMetaData.Bin

// DeployVerifier deploys a new Ethereum contract, binding an instance of Verifier to it.
func DeployVerifier(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Verifier, error) {
	parsed, err := VerifierMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(VerifierBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Verifier{VerifierCaller: VerifierCaller{contract: contract}, VerifierTransactor: VerifierTransactor{contract: contract}, VerifierFilterer: VerifierFilterer{contract: contract}}, nil
}

// Verifier is an auto generated Go binding around an Ethereum contract.
type Verifier struct {
	VerifierCaller     // Read-only binding to the contract
	VerifierTransactor // Write-only binding to the contract
	VerifierFilterer   // Log filterer for contract events
}

// VerifierCaller is an auto generated read-only Go binding around an Ethereum contract.
type VerifierCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VerifierTransactor is an auto generated write-only Go binding around an Ethereum contract.
type VerifierTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VerifierFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type VerifierFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VerifierSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type VerifierSession struct {
	Contract     *Verifier         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// VerifierCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type VerifierCallerSession struct {
	Contract *VerifierCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// VerifierTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type VerifierTransactorSession struct {
	Contract     *VerifierTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// VerifierRaw is an auto generated low-level Go binding around an Ethereum contract.
type VerifierRaw struct {
	Contract *Verifier // Generic contract binding to access the raw methods on
}

// VerifierCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type VerifierCallerRaw struct {
	Contract *VerifierCaller // Generic read-only contract binding to access the raw methods on
}

// VerifierTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type VerifierTransactorRaw struct {
	Contract *VerifierTransactor // Generic write-only contract binding to access the raw methods on
}

// NewVerifier creates a new instance of Verifier, bound to a specific deployed contract.
func NewVerifier(address common.Address, backend bind.ContractBackend) (*Verifier, error) {
	contract, err := bindVerifier(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Verifier{VerifierCaller: VerifierCaller{contract: contract}, VerifierTransactor: VerifierTransactor{contract: contract}, VerifierFilterer: VerifierFilterer{contract: contract}}, nil
}

// NewVerifierCaller creates a new read-only instance of Verifier, bound to a specific deployed contract.
func NewVerifierCaller(address common.Address, caller bind.ContractCaller) (*VerifierCaller, error) {
	contract, err := bindVerifier(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &VerifierCaller{contract: contract}, nil
}

// NewVerifierTransactor creates a new write-only instance of Verifier, bound to a specific deployed contract.
func NewVerifierTransactor(address common.Address, transactor bind.ContractTransactor) (*VerifierTransactor, error) {
	contract, err := bindVerifier(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &VerifierTransactor{contract: contract}, nil
}

// NewVerifierFilterer creates a new log filterer instance of Verifier, bound to a specific deployed contract.
func NewVerifierFilterer(address common.Address, filterer bind.ContractFilterer) (*VerifierFilterer, error) {
	contract, err := bindVerifier(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &VerifierFilterer{contract: contract}, nil
}

// bindVerifier binds a generic wrapper to an already deployed contract.
func bindVerifier(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := VerifierMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Verifier *VerifierRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Verifier.Contract.VerifierCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Verifier *VerifierRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Verifier.Contract.VerifierTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Verifier *VerifierRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Verifier.Contract.VerifierTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Verifier *VerifierCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Verifier.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Verifier *VerifierTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Verifier.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Verifier *VerifierTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Verifier.Contract.contract.Transact(opts, method, params...)
}

// CompressProof is a free data retrieval call binding the contract method 0xb1c3a00e.
//
// Solidity: function compressProof(uint256[8] proof, uint256[2] commitments, uint256[2] commitmentPok) view returns(uint256[4] compressed, uint256[1] compressedCommitments, uint256 compressedCommitmentPok)
func (_Verifier *VerifierCaller) CompressProof(opts *bind.CallOpts, proof [8]*big.Int, commitments [2]*big.Int, commitmentPok [2]*big.Int) (struct {
	Compressed              [4]*big.Int
	CompressedCommitments   [1]*big.Int
	CompressedCommitmentPok *big.Int
}, error) {
	var out []interface{}
	err := _Verifier.contract.Call(opts, &out, "compressProof", proof, commitments, commitmentPok)

	outstruct := new(struct {
		Compressed              [4]*big.Int
		CompressedCommitments   [1]*big.Int
		CompressedCommitmentPok *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Compressed = *abi.ConvertType(out[0], new([4]*big.Int)).(*[4]*big.Int)
	outstruct.CompressedCommitments = *abi.ConvertType(out[1], new([1]*big.Int)).(*[1]*big.Int)
	outstruct.CompressedCommitmentPok = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// CompressProof is a free data retrieval call binding the contract method 0xb1c3a00e.
//
// Solidity: function compressProof(uint256[8] proof, uint256[2] commitments, uint256[2] commitmentPok) view returns(uint256[4] compressed, uint256[1] compressedCommitments, uint256 compressedCommitmentPok)
func (_Verifier *VerifierSession) CompressProof(proof [8]*big.Int, commitments [2]*big.Int, commitmentPok [2]*big.Int) (struct {
	Compressed              [4]*big.Int
	CompressedCommitments   [1]*big.Int
	CompressedCommitmentPok *big.Int
}, error) {
	return _Verifier.Contract.CompressProof(&_Verifier.CallOpts, proof, commitments, commitmentPok)
}

// CompressProof is a free data retrieval call binding the contract method 0xb1c3a00e.
//
// Solidity: function compressProof(uint256[8] proof, uint256[2] commitments, uint256[2] commitmentPok) view returns(uint256[4] compressed, uint256[1] compressedCommitments, uint256 compressedCommitmentPok)
func (_Verifier *VerifierCallerSession) CompressProof(proof [8]*big.Int, commitments [2]*big.Int, commitmentPok [2]*big.Int) (struct {
	Compressed              [4]*big.Int
	CompressedCommitments   [1]*big.Int
	CompressedCommitmentPok *big.Int
}, error) {
	return _Verifier.Contract.CompressProof(&_Verifier.CallOpts, proof, commitments, commitmentPok)
}

// VerifyCompressedProof is a free data retrieval call binding the contract method 0x317297ea.
//
// Solidity: function verifyCompressedProof(uint256[4] compressedProof, uint256[1] compressedCommitments, uint256 compressedCommitmentPok, uint256[1] input) view returns()
func (_Verifier *VerifierCaller) VerifyCompressedProof(opts *bind.CallOpts, compressedProof [4]*big.Int, compressedCommitments [1]*big.Int, compressedCommitmentPok *big.Int, input [1]*big.Int) error {
	var out []interface{}
	err := _Verifier.contract.Call(opts, &out, "verifyCompressedProof", compressedProof, compressedCommitments, compressedCommitmentPok, input)

	if err != nil {
		return err
	}

	return err

}

// VerifyCompressedProof is a free data retrieval call binding the contract method 0x317297ea.
//
// Solidity: function verifyCompressedProof(uint256[4] compressedProof, uint256[1] compressedCommitments, uint256 compressedCommitmentPok, uint256[1] input) view returns()
func (_Verifier *VerifierSession) VerifyCompressedProof(compressedProof [4]*big.Int, compressedCommitments [1]*big.Int, compressedCommitmentPok *big.Int, input [1]*big.Int) error {
	return _Verifier.Contract.VerifyCompressedProof(&_Verifier.CallOpts, compressedProof, compressedCommitments, compressedCommitmentPok, input)
}

// VerifyCompressedProof is a free data retrieval call binding the contract method 0x317297ea.
//
// Solidity: function verifyCompressedProof(uint256[4] compressedProof, uint256[1] compressedCommitments, uint256 compressedCommitmentPok, uint256[1] input) view returns()
func (_Verifier *VerifierCallerSession) VerifyCompressedProof(compressedProof [4]*big.Int, compressedCommitments [1]*big.Int, compressedCommitmentPok *big.Int, input [1]*big.Int) error {
	return _Verifier.Contract.VerifyCompressedProof(&_Verifier.CallOpts, compressedProof, compressedCommitments, compressedCommitmentPok, input)
}

// VerifyProof is a free data retrieval call binding the contract method 0x43db3c72.
//
// Solidity: function verifyProof(uint256[8] proof, uint256[2] commitments, uint256[2] commitmentPok, uint256[1] input) view returns()
func (_Verifier *VerifierCaller) VerifyProof(opts *bind.CallOpts, proof [8]*big.Int, commitments [2]*big.Int, commitmentPok [2]*big.Int, input [1]*big.Int) error {
	var out []interface{}
	err := _Verifier.contract.Call(opts, &out, "verifyProof", proof, commitments, commitmentPok, input)

	if err != nil {
		return err
	}

	return err

}

// VerifyProof is a free data retrieval call binding the contract method 0x43db3c72.
//
// Solidity: function verifyProof(uint256[8] proof, uint256[2] commitments, uint256[2] commitmentPok, uint256[1] input) view returns()
func (_Verifier *VerifierSession) VerifyProof(proof [8]*big.Int, commitments [2]*big.Int, commitmentPok [2]*big.Int, input [1]*big.Int) error {
	return _Verifier.Contract.VerifyProof(&_Verifier.CallOpts, proof, commitments, commitmentPok, input)
}

// VerifyProof is a free data retrieval call binding the contract method 0x43db3c72.
//
// Solidity: function verifyProof(uint256[8] proof, uint256[2] commitments, uint256[2] commitmentPok, uint256[1] input) view returns()
func (_Verifier *VerifierCallerSession) VerifyProof(proof [8]*big.Int, commitments [2]*big.Int, commitmentPok [2]*big.Int, input [1]*big.Int) error {
	return _Verifier.Contract.VerifyProof(&_Verifier.CallOpts, proof, commitments, commitmentPok, input)
}
