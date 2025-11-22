import std/[random, sequtils, openssl]
import ./[config, utils]
import nimcrypto
import checksums/sha2

randomize()
var 
    global_key*: array[16, byte]
    global_key_hash*: array[32, byte]
    aes_key*: array[16, byte]
    hmac_key*: array[16, byte]

for i in 0..15: global_key[i] = rand(255).byte
var global_key_char: array[16, char]
for i in 0..<16: global_key_char[i] = global_key[i].char
var hasher = initSha_256()
hasher.update(global_key_char)
let digest = hasher.digest()

for i in 0..31: global_key_hash[i] = digest[i].byte
for i in 0..15: aes_key[i] = global_key_hash[i]
for i in 0..15: hmac_key[i] = global_key_hash[i+16]
dbg "[+] crypt initialized: \n\tglobal_key:" & repr(global_key) &
        "\n\tglobal_key_hash: " & repr(global_key_hash) &
        "\n\taes_key: " & repr(aes_key) &
        "\n\thmac_key: " & repr(hmac_key)

proc get_iv(): array[16, byte] = 
    for i in 0..15: result[i] = "abcdefghijklmnop"[i].byte

proc padding(data: var seq[byte], block_size: int) =
    var pad = 97.byte # 'A'
    while data.len mod block_size != 0:
        data.add(pad)

# See https://forum.nim-lang.org/t/8060
proc rsa_encrypt*(data: seq[byte]): seq[byte]=
    var plaintext = toString(data)
    var key = rsa_public_key
    var rsa_pub: PRSA
    var bio_pub = BIO_new_mem_buf(addr key[0], -1)
    rsa_pub = PEM_read_bio_RSA_PUBKEY(bio_pub, rsa_pub.addr, nil, nil)
    if rsa_pub.isNil:
        dbg "[-] failed to load public key"
        return
    var cipher_text = newString(RSA_size(rsa_pub))
    doAssert plaintext.len < RSA_size(rsa_pub) - 11
    # differ from original discussion, cast ptr char to ptr uint8 is needed
    let sz = RSA_public_encrypt(plaintext.len.cint, cast[ptr uint8](plaintext[0].addr), cast[ptr uint8](cipher_text[0].addr), rsa_pub, RSA_PKCS1_PADDING)
    if sz != RSA_size(rsa_pub):
        dbg "[-] rsa encrypt failed"
        return
    return toSeq(cipher_text)

proc rsa_encrypt2*(data: seq[byte]): seq[byte] =
    let pemKey = rsa_public_key.toSeq
    var bio = BIO_new_mem_buf(pemKey[0].addr, pemKey.len.cint)
    var rsaPub: PRSA
    rsaPub = PEM_read_bio_RSA_PUBKEY(bio, rsaPub.addr, nil, nil)
    if rsaPub.isNil:
        dbg "[-] failed to load public key"
        return
    let keySize = RSA_size(rsaPub)
    var outBuf = newSeq[byte](keySize)
    if data.len > int(keySize) - 11:
        dbg "[-] rsa encrypt failed"
        return outBuf
    let encLen = RSA_public_encrypt(
        data.len.cint,
        data[0].addr,
        outBuf[0].addr,
        rsaPub,
        RSA_PKCS1_PADDING
    )
    if encLen < 0:
        dbg "[-] rsa encrypt failed"
        return outBuf

    if encLen < keySize:
        outBuf.setLen(encLen)
    return outBuf

proc aes_decrypt*(cipher: seq[byte]): seq[byte] =
    # dbg "[+] aes decrypt: " & repr(cipher) & ", key: " & repr(aes_key) & ", iv: " & repr(get_iv())
    var res_arr = newSeq[byte](cipher.len+aes128.sizeBlock)
    var dctx: CBC[aes128]
    dctx.init(aes_key, get_iv())
    dctx.decrypt(cipher, res_arr)
    # dbg "[+] aes decrypt result " & repr(res_arr)
    dctx.clear()
    return res_arr.toSeq

proc aes_encrypt*(plaintext: var seq[byte]): seq[byte] =
    var ectx: CBC[aes128]
    ectx.init(aes_key, get_iv())
    padding(plaintext, aes128.sizeBlock)
    # dbg "[+] aes encrypt: " & repr(plaintext) & ", block size: " & $aes128.sizeBlock
    var res_arr = newSeq[byte](plaintext.len)
    ectx.encrypt(plaintext, res_arr)
    ectx.clear()
    return res_arr

# TODO
proc verify_hmac_hash*(hash: seq[byte]): bool = 
    dbg "[+] got hmac hash: " & $hash
    true
    
proc hmac_hash*(data: openArray[byte]): seq[byte] =
    var hctx: HMAC[sha256]
    hctx.init(hmac_key)
    hctx.update(data)
    result = @(hctx.finish().data[0..15])
    hctx.clear()