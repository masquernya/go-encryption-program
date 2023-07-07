# Go Encryption Program Demo

**This is just a demo, I don't know for sure if everything is implemented properly.** If you have any questions or suggestions, please open an issue.

This is a demo program that uses elliptic curve cryptography to encrypt and decrypt files, as an alternative to RSA. To be specific, it uses [NaCL Box](https://pkg.go.dev/golang.org/x/crypto/nacl/box) for most of the work, which in turn uses [Curve25519](https://en.wikipedia.org/wiki/Curve25519) and [XSalsa20](https://en.wikipedia.org/wiki/Salsa20). It uses io.Reader for reading files (instead of byte arrays), so it can be used to encrypt files of any size (with a chunk size based on the size of the file - either the size of the file itself, or 128MB, whichever is smaller).

You only need a public key to encrypt files, though you need both the public and private key to decrypt them. This is similar to RSA encryption, at least from the user's perspective.

## Security Notes

- Your private key is not encrypted. It is your responsibility to keep it safe, such as by keeping it in a password manager.
- The length of an encrypted file is not hidden and can be figured out.

## Binary Format

```
[4 bytes] Magic Bytes ("OwO1")
[4 bytes] Chunk Size (int32, big endian)
[...]     Encrypted Data, exactly chunk size + 48 until end of file. The final chunk may be smaller than the chunk size.
```

## Verified Compatibility

**encrypt-nacl** and **decrypt-nacl** commands:
- C#
  - [ASP.Net Sodium.Core](https://www.nuget.org/packages/Sodium.Core/) (Sodium.SealedPublicKeyBox API)

**encrypt-file** and **decrypt-file** commands:

Nothing!