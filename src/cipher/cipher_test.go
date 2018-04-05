package cipher

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/skycoin/skycoin/src/cipher/base58"
	secp256k1 "github.com/skycoin/skycoin/src/cipher/secp256k1-go"
	secp "github.com/skycoin/skycoin/src/cipher/secp256k1-go/secp256k1-go2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSha256(t *testing.T) {
	sha := secp256k1.SumSHA256([]byte("3100486406b39efc3f3d3565bc97cc3b9e2d7b6e3427b194f4442ef4beb05b41"))
	shasum := hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("cb7b3ba8a7b4a666f6d46c863cf7690cb0ba8468338ce25557f67312cb15f4ff"))

	sha = secp256k1.SumSHA256([]byte(""))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

	sha = secp256k1.SumSHA256([]byte(""))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

	sha = secp256k1.SumSHA256([]byte("1234567890_1"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("3eda9ffe5537a588f54d0b2a453e5fa932986d0bc0f9556924f5c2379b2c91b0"))

	sha = secp256k1.SumSHA256([]byte("1234567890_2"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("a144d0b4d285260ebbbab6840baceaa09eab3e157443c9458de764b7262c8ace"))

	sha = secp256k1.SumSHA256([]byte("1234567890_3"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("9f839169d293276d1b799707d2171ac1fd5b78d0f3bc7693dbed831524dd2d77"))

	sha = secp256k1.SumSHA256([]byte("1234567890_4"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("6c5fe2a8e3de58a5e5ac061031a8e802ae1fb9e7197862ec1aedf236f0e23475"))

	sha = secp256k1.SumSHA256([]byte("024f7fd15da6c7fc7d0410d184073ef702104f82452da9b3e3792db01a8b7907c3"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("a5daa8c9d03a9ec500088bdf0123a9d865725b03895b1291f25500737298e0a9"))
}

func TestSha256Cipher(t *testing.T) {
	sha := SumSHA256([]byte("3100486406b39efc3f3d3565bc97cc3b9e2d7b6e3427b194f4442ef4beb05b41"))
	shasum := hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("cb7b3ba8a7b4a666f6d46c863cf7690cb0ba8468338ce25557f67312cb15f4ff"))

	sha = SumSHA256([]byte(""))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

	sha = SumSHA256([]byte(""))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

	sha = SumSHA256([]byte("1234567890_1"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("3eda9ffe5537a588f54d0b2a453e5fa932986d0bc0f9556924f5c2379b2c91b0"))

	sha = SumSHA256([]byte("1234567890_2"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("a144d0b4d285260ebbbab6840baceaa09eab3e157443c9458de764b7262c8ace"))

	sha = SumSHA256([]byte("1234567890_3"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("9f839169d293276d1b799707d2171ac1fd5b78d0f3bc7693dbed831524dd2d77"))

	sha = SumSHA256([]byte("1234567890_4"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("6c5fe2a8e3de58a5e5ac061031a8e802ae1fb9e7197862ec1aedf236f0e23475"))

	sha = SumSHA256([]byte("024f7fd15da6c7fc7d0410d184073ef702104f82452da9b3e3792db01a8b7907c3"))
	shasum = hex.EncodeToString(sha[:])

	require.Equal(t, []byte(shasum[:]), []byte("a5daa8c9d03a9ec500088bdf0123a9d865725b03895b1291f25500737298e0a9"))
}

func TestSecp256k1GenerateDeterministicKeyPair(t *testing.T) {
	seed := []byte("3100486406b39efc3f3d3565bc97cc3b9e2d7b6e3427b194f4442ef4beb05b41")

	seedO, pubkey, seckey := secp256k1.DeterministicKeyPairIterator(seed)

	fmt.Printf("seedO %x\n", seedO)
	fmt.Printf("pubkey %x\n", pubkey)
	fmt.Printf("seckey %x\n", seckey)

	require.Equal(t, []byte(hex.EncodeToString(seckey[:])), []byte("99f69bc8c041e13b1d90e49d560b8536d839db0eee87f9c9b4353ffb4391ff87"))

}

func TestEDCH(t *testing.T) {
	_, sec1 := GenerateKeyPair()
	pub2, _ := GenerateKeyPair()

	fmt.Printf("sec1 %x\n", sec1)
	fmt.Printf("pub2 %x\n", pub2)

	var bpub [33]byte
	var bsec [32]byte
	bpub1, _ := hex.DecodeString("02683e90daa5b0dd195b69e01386390284d3b3723121ce213771d9a0815d12b86c")
	bsec2, _ := hex.DecodeString("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04")
	copy(bpub[:], bpub1)
	copy(bsec[:], bsec2)

	fmt.Printf("bsec2 %x\n", bsec2)
	fmt.Printf("bpub1 %x\n", bpub1)

	// fmt.Printf("my_pubkey %x\nmy_seckey %x\n", bpub, bsec)

	buf1 := ECDH(pub2, sec1)
	buf2 := ECDH(PubKey(bpub), SecKey(bsec))

	// fmt.Printf("Ecdh %x\n", buf2)

	assert.True(t, bytes.Equal(buf1, buf2))
}

func TestGenerateSeckey(t *testing.T) {

	success := true
	seed := secp256k1.SumSHA256([]byte("seed"))

	fmt.Printf("Seed: %s len: %d\n", hex.EncodeToString(seed[:]), len(seed))
	if seed == nil {
		log.Panic()
		success = false
	}
	if len(seed) != 32 {
		log.Panic()
		success = false
	}

new_seckey:
	seed = secp256k1.SumSHA256(seed[0:32])

	fmt.Printf("Sha256Seed: %x\n", seed)

	const seckeyLen = 32
	var seckey = make([]byte, seckeyLen)
	copy(seckey[0:32], seed[0:32])

	fmt.Printf("Seckey: %x\n", seckey)

	if bytes.Equal(seckey, seed) == false {
		log.Panic()
		success = false
	}
	if secp.SeckeyIsValid(seckey) != 1 {
		log.Printf("generateDeterministicKeyPair, secp.SeckeyIsValid fail")
		goto new_seckey //regen
	}

	require.Equal(t, []byte(hex.EncodeToString(seckey[:])), []byte("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04"))

	assert.True(t, success)
}

func TestGeneratePublicKeyFromSeckey(t *testing.T) {
	seckey := []byte("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04")
	seckey, _ = hex.DecodeString(string(seckey))

	fmt.Printf("seckey: %x\n", seckey)

	var pubkey = secp.GeneratePublicKey(seckey)
	fmt.Printf("pubkey: %x\n", pubkey)

	assert.True(t, false)
}

func TestSecp256k1Hash(t *testing.T) {
	seed := []byte("seed")
	hash := secp256k1.Secp256k1Hash(seed)
	hexhash := hex.EncodeToString(hash[:])
	require.Equal(t, []byte(hexhash[:]), []byte("c79454cf362b3f55e5effce09f664311650a44b9c189b3c8eed1ae9bd696cd9e"))

	seed = []byte("024f7fd15da6c7fc7d0410d184073ef702104f82452da9b3e3792db01a8b7907c3")
	hash = secp256k1.Secp256k1Hash(seed)
	hexhash = hex.EncodeToString(hash[:])
	fmt.Printf("hexhash %s\n", hexhash)
	require.Equal(t, []byte(hexhash[:]), []byte("022750e4611d328f280b5256b3fdf8baf545072db6fcb0547b1472835cd32727"))
}

func TestDeterministicKeyPairIterator(t *testing.T) {
	seed := []byte("seed")
	_, pubkey, seckey := secp256k1.DeterministicKeyPairIterator(seed)
	hexpubkey := hex.EncodeToString(pubkey[:])
	hexseckey := hex.EncodeToString(seckey[:])
	require.Equal(t, []byte(hexpubkey[:]), []byte("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"))
	require.Equal(t, []byte(hexseckey[:]), []byte("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"))

	seed = []byte("random_seed")
	_, pubkey, seckey = secp256k1.DeterministicKeyPairIterator(seed)
	hexpubkey = hex.EncodeToString(pubkey[:])
	hexseckey = hex.EncodeToString(seckey[:])
	require.Equal(t, []byte(hexpubkey[:]), []byte("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73"))
	require.Equal(t, []byte(hexseckey[:]), []byte("ff671860c58aad3f765d8add25046412dabf641186472e1553435e6e3c4a6fb0"))

	seed = []byte("hello seed")
	_, pubkey, seckey = secp256k1.DeterministicKeyPairIterator(seed)
	hexpubkey = hex.EncodeToString(pubkey[:])
	hexseckey = hex.EncodeToString(seckey[:])
	fmt.Printf("pubkey %x\n", pubkey)
	fmt.Printf("seckey %x\n", seckey)
	require.Equal(t, []byte(hexpubkey[:]), []byte("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0"))
	require.Equal(t, []byte(hexseckey[:]), []byte("84fdc649964bf299a787cb78cd975910e197dbddd7db776ece544f41c44b3056"))

}

func TestToAddressHashInternal(t *testing.T) {
	p, _ := hex.DecodeString("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1")
	pubkey := NewPubKey(p)
	h := pubkey.ToAddressHash()
	fmt.Printf("hex h: %x\n", h)
	hexaddress := hex.EncodeToString(h[:])
	require.Equal(t, []byte(hexaddress[:]), []byte("b1aa8dd3e68d1d9b130c67ea1339ac9250b7d845"))

	fmt.Printf("converted h: %s\n", string(base58.Hex2Base58([]byte(h[:]))))
	require.Equal(t, string(base58.Hex2Base58([]byte(h[:]))), string("2EVNa4CK9SKosT4j1GEn8SuuUUEAXaHAMbM"))
}

func TestAddressFromPubkeyInternal(t *testing.T) {
	p, _ := hex.DecodeString("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1")
	pubkey := NewPubKey(p)
	h := AddressFromPubKey(pubkey)
	fmt.Printf("h: %s\n", string(base58.Hex2Base58(h.Bytes())))

	p, _ = hex.DecodeString("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73")
	pubkey = NewPubKey(p)
	h = AddressFromPubKey(pubkey)
	require.Equal(t, h.String(), string("2EKq1QXRmfe7jsWzNdYsmyoz8q3VkwkLsDJ"))

	p, _ = hex.DecodeString("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0")
	pubkey = NewPubKey(p)
	h = AddressFromPubKey(pubkey)
	require.Equal(t, h.String(), string("5UgkXRHrf5XRk41BFq1DVyeFZHTQXirhUu"))
}

func TestAddressBitcoin(t *testing.T) {

	p, _ := hex.DecodeString("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1")
	pubkey := NewPubKey(p)
	h := BitcoinAddressFromPubkey(pubkey)
	fmt.Printf("hex h: %s\n", h)
	require.Equal(t, h[:], string("1CN7JTzTTpmh1dsHeUSosXmNL2GLTwt78g"))

	p, _ = hex.DecodeString("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73")
	pubkey = NewPubKey(p)
	h = BitcoinAddressFromPubkey(pubkey)
	require.Equal(t, h, string("1DkKGd1YV9nhBKHWT9Aa2JzbEus98y6oU9"))

	p, _ = hex.DecodeString("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0")
	pubkey = NewPubKey(p)
	h = BitcoinAddressFromPubkey(pubkey)
	require.Equal(t, h, string("1Ba2hpHH2o6H1NSrFpJTz5AbxdB2BdK5L2"))
}

func TestAddressBitcoinPrivate(t *testing.T) {

	s, _ := hex.DecodeString("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7")
	seckey := NewSecKey(s)
	h := BitcoinWalletImportFormatFromSeckey(seckey)
	fmt.Printf("hex h: %s\n", h)
	require.Equal(t, h[:], string("KwDuvkABDqb4WQiwc92DpXtBBiEywuKv46ZUvz5Gi5Xyn9gbcTJt"))

	s, _ = hex.DecodeString("ff671860c58aad3f765d8add25046412dabf641186472e1553435e6e3c4a6fb0")
	seckey = NewSecKey(s)
	h = BitcoinWalletImportFormatFromSeckey(seckey)
	require.Equal(t, h, string("L5nBR59QkW6kyXFvyqNbncWo2jPMoBXSH9fGUkh3n2RQn5Mj3vfY"))

	s, _ = hex.DecodeString("84fdc649964bf299a787cb78cd975910e197dbddd7db776ece544f41c44b3056")
	seckey = NewSecKey(s)
	h = BitcoinWalletImportFormatFromSeckey(seckey)
	require.Equal(t, h, string("L1gEDGuLTpMjybHnsJ24bUHhueocDrrKVdM3rj1rqXFHfyM2WtwD"))
}

func TestSignature(t *testing.T) {

	seed := []byte("different")
	message := []byte("This msg has 32 characters: max.")
	// message, _ := hex.DecodeString("de4e9524586d6fce45667f9ff12f661e79870c4105fa0fb58af976619bb11432")
	_, pubkey, seckey := secp256k1.DeterministicKeyPairIterator(seed)
	// hexpubkey := hex.EncodeToString(pubkey[:])
	// hexseckey := hex.EncodeToString(seckey[:])
	// require.Equal(t, []byte(hexpubkey[:]), []byte("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"))
	// require.Equal(t, []byte(hexseckey[:]), []byte("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"))

	fmt.Printf("pubkey: %x\n", pubkey)
	fmt.Printf("seckey: %x\n", seckey)
	signature := secp256k1.Sign(message, seckey)
	fmt.Printf("signature: %x\n", signature)
	//assert.Equal(t, signature, expectedSignature) // signature changes every time (random nonce)
	assert.Equal(t, 1, secp256k1.VerifySignature(message, signature, pubkey))
	assert.True(t, false)
}

func TestPubkeyFromSignature(t *testing.T) {

	message := []byte("Hello World!")
	signature, _ := hex.DecodeString("abc30130e2d9561fa8eb9871b75b13100689937dfc41c98d611b985ca25258c960be25c0b45874e1255f053863f6e175300d7e788d8b93d6dcfa9377120e4d3500")
	expectedPubkey, _ := hex.DecodeString("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1")
	fmt.Printf("message: %s\n", message)
	hexmsg, _ := hex.DecodeString(string(message))
	fmt.Printf("hexa msg = %x\n", hexmsg)
	fmt.Printf("signature: %x\n", signature)
	fmt.Printf("expectedPubkey: %x\n", expectedPubkey)
	pubkey := secp256k1.RecoverPubkey(message, signature)
	fmt.Printf("pubkey: %x\n", pubkey)
	assert.Equal(t, pubkey, expectedPubkey)
	assert.Equal(t, len(pubkey), 33)

	message = []byte("Hello World, it's me!")
	signature, _ = hex.DecodeString("00b0dbb50c8b8f6c5be2bdee786a658a0ea22872ce90b21fbc0eb4f1d1018a043f93216a6af467acfb44aef9ab07e0a65621128504f3a61dfa0014b1cdd6d9c701")

	pubkey = secp256k1.RecoverPubkey(message, signature)
	fmt.Printf("pubkey: %x\n", pubkey)
	assert.Equal(t, pubkey, expectedPubkey)

	message = []byte("Hello World, it's me!")
	signature, _ = hex.DecodeString("54d7572cf5066225f349d89ad6d19e19e64d14711083f6607258b37407e5f0d26c6328d7c3ecb31eb4132f6b983f8ec33cdf3664c1df617526bbac140cdac75b01")

	pubkey = secp256k1.RecoverPubkey(message, signature)
	fmt.Printf("pubkey: %x\n", pubkey)
	assert.Equal(t, pubkey, expectedPubkey)
	// assert.True(t, false)
}

func TestB32(t *testing.T) {
	sigByte, _ := hex.DecodeString("abc30130e2d9561fa8eb9871b75b13100689937dfc41c98d611b985ca25258c960be25c0b45874e1255f053863f6e175300d7e788d8b93d6dcfa9377120e4d3500")
	var sig secp.Signature
	sig.ParseBytes(sigByte[0:64])

	var rx secp.Number
	rx.Set(&sig.R.Int)
	rxbin, _ := hex.DecodeString("abc30130e2d9561fa8eb9871b75b13100689937dfc41c98d611b985ca25258c9")
	var fx secp.Field
	fmt.Printf("rxbin: %x\n", rxbin)
	fx.SetB32(rxbin)
	fmt.Printf("fx: %x\n", fx)
	fx.Print("fx value")

	assert.True(t, false)
}

func TestRecoverPubkeyFromSignature(t *testing.T) {

	message := []byte("Hello World")
	signature, _ := hex.DecodeString("abc30130e2d9561fa8eb9871b75b13100689937dfc41c98d611b985ca25258c960be25c0b45874e1255f053863f6e175300d7e788d8b93d6dcfa9377120e4d3500")
	expectedPubkey, _ := hex.DecodeString("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1")

	var sig secp.Signature
	var recid = int(signature[64])
	fmt.Printf("recid: %x\n", recid)
	sig.ParseBytes(signature[0:64])
	var msg secp.Number

	var pubkey secp.XY

	msg.SetBytes(message)
	sig.Recover(&pubkey, &msg, recid)
	fmt.Printf("pubkey: %x\n", pubkey.Bytes())

	// assert.Equal(t, pubkey.Bytes(), expectedPubkey)

	message = []byte("Hello World, it's me!")
	msg.SetBytes(message)
	signature, _ = hex.DecodeString("00b0dbb50c8b8f6c5be2bdee786a658a0ea22872ce90b21fbc0eb4f1d1018a043f93216a6af467acfb44aef9ab07e0a65621128504f3a61dfa0014b1cdd6d9c701")
	recid = int(signature[64])
	fmt.Printf("recid: %x\n", recid)

	sig.ParseBytes(signature[0:64])
	sig.Recover(&pubkey, &msg, recid)
	fmt.Printf("pubkey: %x\n", pubkey.Bytes())

	assert.Equal(t, pubkey.Bytes(), expectedPubkey)

	assert.True(t, false)
}
