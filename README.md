# `import Signature`

![Swift 3.0](https://img.shields.io/badge/Swift-3.0-ee4f37.svg)
![Licence](https://img.shields.io/badge/Licence-MIT-000000.svg)
[![Build Status](https://travis-ci.org/alexaubry/Signature.svg?branch=master)](https://travis-ci.org/alexaubry/Signature)

`Signature` is a Swift library that allows you to sign and verify messages.

## Features

- [x] HMAC signature and verification
- [x] Private Key signature and Public Key verification (ECDSA, RSA, ...)
- [x] Unit-tested

## Installation

`Signature` is compatible with Linux and macOS via the Swift Package Manager. To include it in your packages, add this line in your `Package.swift` :

~~~swift
.Package(url: "https://github.com/alexaubry/Signature.git", majorversion: 1)
~~~

## API Overview

~~~swift
let megaRandomBytes = [0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f]

// HMAC

let hmacKey = try HMACKey(password: "secret")
let hmacSHA256Signature = try Signature.sign(message: megaRandomBytes, with: hmacKey, using: .sha256)
let isHMACSignatureValid = try Signature.verify(signature: hmacSHA256Signature, expectedMessage: megaRandomBytes, key: hmacKey, hashingAlgorithm: .sha256) 

// ECDSA

let ecdsaPublicKey = try CryptoKey(path: "/path/to/ecdsa_publicKey.pem", component: .publicKey)
let ecdsaPrivateKey = try CryptoKey(path: "/path/to/ecdsa_privateKey.pem", component: .privateKey(passphrase: nil))
let ecdsaSHA512Signature = try Signature.sign(message: megaRandomBytes, with: ecdsaPrivateKey, using: .sha512)
let isECDSASignatureValid = try Signature.verify(signature: ecdsaSHA512Signature, expectedMessage: megaRandomBytes, key: ecdsaPublicKey, hashingAlgorithm: .sha512)

// RSA

let rsaPublicKey = try CryptoKey(path: "/path/to/rsa_publicKey.pem", component: .publicKey)
let rsaPrivateKey = try CryptoKey(path: "/path/to/rsa_privateKey.pem", component: .privateKey(passphrase: "passphrase"))
let rsaRMD160Signature = try Signature.sign(message: megaRandomBytes, with: rsaPrivateKey, using: .ripeMd160)
let isRSASignatureValid = try Signature.verify(signature: rsaRMD160Signature.bytes, expectedMessage: megaRandomBytes, key: rsaPublicKey, hashingAlgorithm: .ripeMd160)
~~~

## Signature

You can compute the signature of a message in very few steps : 

1. Create a key (see [Keys](#keys) for more info)
2. Select a hashing algorithm. All the compatible algorithms are listed in [this file](https://github.com/alexaubry/Hash/blob/1.0.1/Sources/Hash.swift#L45).
3. Call `Sign.sign(bytes:,with:,using:)` to get the `Data` object containing the signature.

**Example** : create the MD5 HMAC of the `"Hello"` string with the `"secret"` password :

~~~swift
// 1- Compute the bytes in "Hello"
let helloBytes = [0x48, 0x65, 0x6c, 0x6c, 0x6f] 

// 2- Create the key (here: HMAC)
let key = try HMACKey(password: "secret")

// 3- Sign with MD5
let signature = try Signature.sign(message: helloBytes, with: key, using: .md5)
~~~

You can sign arrays of bytes and objects conforming to the `BytesConvertible` protocol (String and Data)

## Verification

1. Get the public key counterpart of the private key you think has created the signature.
2. Determine the hashing algorithm that should have been used.
3. Call `Signature.verify(signature:,expectedMessage:,key:,hashingAlgorithm:)`. If it returns `true`, the signature is valid. If not, the signature is invalid.

**Example** : We have a user in a database. We store her public key with the id "123". We receive a message from her. We want to check that it has been signed with her private key. We expect the signature to be an _ECDSA-with-SHA256_ signature.

~~~swift
// - variable messageBytes: the message we have received from the user
// - variable messageSignature: the signature of the message we have received from the user

let publicKey = try CryptoKey(path: "/path/to/123.pem", component: .publicKey)
let result = try Signature.verify(signature: messageSignature, expectedMessage: messageBytes, key: publicKey, hashingAlgorithm: .sha256)

print(result ? "The signature is valid." : "The signature is not valid.")
~~~

You can verify arrays of bytes and objects conforming to the `BytesConvertible` protocol (String and Data)

### Note : HMAC Verification

The concept of public/private keys do not exist in HMAC. To verify a signature with HMAC, recreate the key from a password.

**Example** : We have a user in a database. We store her HMAC password with the id "123". We receive a message from her. We want to check that it has been signed with her HMAC key. We expect the signature to be an _HMAC-with-SHA256_ signature.

~~~swift
// - variable messageBytes: the message we have received from the user
// - variable messageSignature: the signature of the message we have received from the user
// - variable hmacPassword: the password we've fetched from our database

let publicKey = try HMAC(password: hmacPassword)
let result = try Signature.verify(signature: messageSignature, expectedMessage: messageBytes, key: publicKey, hashingAlgorithm: .sha256)

print(result ? "The signature is valid." : "The signature is not valid.")
~~~

## <a name="keys"></a> Keys

In this library, there are two type of keys : HMAC keys and public/private key pairs.

### HMAC Keys

HMAC keys are used to create HMACs. They are contained in the `HMACKey` objects. They are based on passwords.

**Example** : creating HMAC keys

~~~swift
let key1 = try HMACKey(password: "secret")
let key2 = try HMACKey(passwordBytes: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
~~~

The `HMACKey(password:)` initializer accepts any object conforming to the `BytesConvertible` protocol.

### Public/Private Key

You can use a public/private key pair to sign messages and verify signatures. This library has been tested with ECDSA and RSA, it may also work with other algorithms (let me know if it does!). Such keys are contained in `CryptoKey` objects.

You create `CryptoKey` objects from **PEM-encoded** key files. You can load public, private and encrypted private keys.

**Example** : loading key pairs

~~~swift
let publicKey = try CryptoKey(path: "/path/to/public_key.pem", component: .publicKey) // loads a public key
let privateKey = try CryptoKey(path: "/path/to/private_key.pem", component: .privateKey(passphrase: nil)) // loads a private key
let privateKey = try CryptoKey(path: "/path/to/encrypted_private_key.pem", component: .privateKey(passphrase: "secret")) // loads an encrypted private key
~~~

## Error Handling

Functions and initializers marked with the `throws` keyword throw a `CryptoError` object in case of failure.
See [CryptoError](https://github.com/alexaubry/CryptoError) for more informations.

## Disclaimer

This cryptographic library has not been audited/validated. Use it at your own risk!

## Acknowledgements

This library relies on [CLibreSSL](https://github.com/vapor/CLibreSSL).

It is also using libraries of my own, which you can check out :

- [Hash](https://github.com/alexaubry/Hash)
- [BytesKit](https://github.com/alexaubry/BytesKit)
- [CryptoError](https://github.com/alexaubry/CryptoError)
- [CryptoLoader](https://github.com/alexaubry/CryptoLoader) 
