package main

import (

	// "encoding/hex"
	"encoding/binary"
	"fmt"

	bls_core "github.com/harmony-one/bls/ffi/go/bls"
	"github.com/harmony-one/harmony/crypto/bls"
	// "github.com/herumi/bls-eth-go-binary/bls"
	// bls_core "github.com/harmony-one/bls/ffi/go/bls"
)


func main() {
	bls_core.Init(bls_core.BLS12_381)

	// fmt.Println("Hello, world.")
	// // 5 = BLS12_381
	if bls_core.Init(5) != nil {
		fmt.Println("fatal init")
	}
	// if bls.SetETHmode(0) != nil {
	// 	fmt.Println("fatal setEthMode")
	// }
	// bls.SetETHserialization(false)
	// bls.SetMapToMode(0)

	 signers := [...]string{
	"e7f54994bc5c02edeeb178ce2d34db276a893bab5c59ac3d7eb9f077c893f9e31171de6236ba0e21be415d8631e45b91",
    	"99d0835797ca0683fb7b1d14a882879652ddcdcfe0d52385ffddf8012ee804d92e5c05a56c9d7fc663678e36a158a28c",
	"8a211eb5e9334341fd2498fb5d6b922b4a0984d6a4ea0b5631c1904de5fe21fd6889c9c032d862546ca50a5c41294b0c",
	"1833721b78797a16b1987734d05b08b9444e24075fda50ff2acc7b8a6d8e0aef0829bcb11e3b9df7466cf8a39e4e4101",
	"8c95e04a4826d4d80ef16183f13aa5d14eb3c96d2755407e15c440bb4edd6e4636a82e47975385c6223ba24759561103",
	"a2b1b534c94bf19a92551f1d32d62b802be6996458f65b0baeb081c9972b34d72310e675fc7797b9c860d8cc223cee8f",
	"f248bd21d67f0b2cd0dd2c06446c557fc35737873857c000698ae391b607ca8ed8df00a79d9dcace1b0ce05492fc9789",
	"ba27796a04c1e4d2cb2d946ac520c2b41589517cb9ae22e64718086c1b13bec1c3d1d78c274d4ffafd78e1b66705e496",
	"ee855bbeca8885cc9c335196af420eb7224e22c8647ca8b418c2b67d25c86cbd4a7435bf3905614ca21fd28bae28e408",
	"e6c33ada02e808fa7c2dd98734648cbb03c30d39e5c5deb5baae89c4b89e3b2356aff11cb94c35d7d955e14e131b4a18",
	"d13e1d260791bda54201d77ff44bab65e628e82a8d96e3804bb2852dc1459ecb59cd788c04a3f1fd3e2c6a5fc3242b84",
	"ead2f549dd09e8486b2b4095a67dddf4473b06fa003ccc6404afae5f5d56b632ccf2f8aae134c8156691e4953ea57c00",
	"cc29030fd7888a9f2aa1176ae972787a87295aae79149e83e2113e4d71f49d473fa3bd89e8db968b8a42141d4673e918",
	"d69c70aa8e43853487760533ad1cbeb9f8e91d409ede23f5db9e0038528bd9914ecd8710afe187bb303cc345a52f0b93",
	"24044191bcc50e6f43dc21d052c88885aadc0c693675d9a418d00d1afd98286658812f17b612658fc433e8eb619b5c00",
	};
	var signature =
	"c247e7747f51581691af06c6f3d80a1dd5d37c6663511079815ea82aeeb5cc5331e1517f378a9e5de04bdacc9f4ab804478ad77af332437b54bd2d4e08d3e50d539b020029c516338a3618501de570469c37bd9f4a4e4bcc61ab217fd08fd187"
	var coreSig bls_core.Sign;
	coreSig.DeserializeHexStr(signature)

	var sigBytes bls.SerializedSignature;
	copy(sigBytes[:], coreSig.Serialize())
	// fmt.Println(len(sigBytes))
	_ = signature
	_ = signers
	// _ = sigBytes
	_ = coreSig;

	var aggregatePublic = &bls_core.PublicKey{}
	for _, signer := range signers {
		// fmt.Printf("signer= %v\n", signer)
		var gen bls_core.PublicKey;
		gen.DeserializeHexStr(signer)
		aggregatePublic.Add(&gen)
	    }
	var blockHash = 
	"0x01fc8590d17fbf7eed40deb9f991eefce89e8ddcfd3f9bb9bc7d4f480a53aee8"
	// // _ = signers;
	blockNumber := uint64(1);
	blockNumBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(blockNumBytes, blockNumber)

	commitPayload := append(blockNumBytes, []byte(blockHash)...)
	viewIDBytes := make([]byte, 8)
	var viewID uint64 = 1;
	binary.LittleEndian.PutUint64(viewIDBytes, viewID)
	commitPayload = append(commitPayload, viewIDBytes...)

	var res = coreSig.VerifyHash(aggregatePublic,commitPayload)
	
	// var multiSign = bls.Sign{};
	// multiSign.SetHexString(signature)
	/**************/
	// var sigBytes bls.SerializedSignature;
	// sigBytes.
	// aggSig := bls_core.Sign{}
	// err := aggSig.Deserialize(sigBytes[:])
	/**************/

	// var res = multiSign.VerifyHash(aggregatePublic,commitPayload)

	fmt.Printf("res=%v\n", res)


	var id bls_core.ID
		err := id.SetLittleEndian([]byte{6, 5, 4, 3, 2, 1})
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("id :", id.SerializeToHexStr())
		var id2 bls_core.ID
		err = id2.DeserializeHexStr(id.SerializeToHexStr())
		if err != nil {
			fmt.Println(err)
		}
		fmt.Print("create secret key")
		m := "this is a bls sample for go"
		var sec bls_core.SecretKey
		sec.SetByCSPRNG()
		fmt.Println("sec:", sec.SerializeToHexStr())
		fmt.Println("create public key")
		pub := sec.GetPublicKey()
		fmt.Println("pub:", pub.SerializeToHexStr())
		sign := sec.Sign(m)
		fmt.Println("sign:", sign.SerializeToHexStr())
		if !sign.Verify(pub, m) {
			fmt.Println("Signature does not verify")
		}
	// var gen bls.PublicKey
	// gen.SetHexString("1 4f58f3d9ee829f9a853f80b0e32c2981be883a537f0c21ad4af17be22e6e9959915ec21b7f9d8cc4c7315f31f3600e5 1212110eb10dbc575bccc44dcd77400f38282c4728b5efac69c0b4c9011bd27b8ed608acd81f027039216a291ac636a8")
	// bls.SetGeneratorOfPublicKey(&gen)

	// var sec bls.SecretKey
	// bytes := []byte{185, 10, 0, 237, 196, 231, 235, 253, 95, 221, 36, 224, 109, 252, 10, 222, 14, 197, 82, 107, 220, 29, 208, 123, 169, 190, 98, 181, 240, 198, 35, 98}
	// sec.Deserialize(bytes)
	// sig := sec.SignHash(bytes)
	// fmt.Printf("sig=%v\n", sig.SerializeToHexStr())
	// //	assertBool("check sig", byteToHexStr(sig.serialize()).equals("2f4ff940216b2f13d75a231b988cd16ef22b45a4709df3461d9baeebfeaafeb54fad86ea7465212f35ceb0af6fe86b1828cf6de9099cefe233d97e0523ba6c0f5eecf4db71f7b1ae08cd098547946abbd0329fdac14d27102f2a1891e9188a19"));A

	// sec.DeserializeHexStr("d243f3f029c188a5b1c4c098f5719cbc967184ef962b5c5d6c72693c92c1f725")
	// pub := sec.GetPublicKey()
	// fmt.Printf("pub=%v\n", pub.SerializeToHexStr())
	// if pub.SerializeToHexStr() != "15ad529698be1f6164fd50416d1991a04b977d9014b43ae9d014ca50ae634829182632d54c7188b3a53e0b77ae4c9e87" {
	// 	fmt.Println("bad pub")
	// }
	// msg, _ := hex.DecodeString("1100000000000000000000000000000000000000000000000000000000000031")
	// sig = sec.SignByte(msg)
	// if sig.SerializeToHexStr() != "2f2071370054ded61081a069dc657d7111ae909fc08a38ae1f3a967c4e4c1b97b7d2ee8adc512ded7213dc0ab2c9db158451eca54a4db26ec013e108d561d8e0eede883b73074d49143ea8e9291903aabce2a2b4f153f99822e4512dac86ae18" {
	// 	fmt.Println("bad sig")
	// }
	// sig = sec.SignHash(msg)
	// if sig.SerializeToHexStr() != "807f6fb074cfdd0318501ef894b127a3f71754745dcff2163dd128091efd065c4ac419e3d7d5428a0b94ada19de657176fb4ccfdb3105f869d6351e503ba20e9d6ef55f179510941db4d131c3678e9d9316090c99bd7d62107d83f6fe5f6f115" {
	// 	fmt.Println("bad sig2")

	// }
}
func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
	    runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
    }