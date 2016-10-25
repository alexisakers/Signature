/*
 * ==---------------------------------------------------------------------------------==
 *
 *  File            :   Signature.swift
 *  Project         :   Signature
 *  Author          :   ALEXIS AUBRY RADANOVIC
 *
 *  License         :   The MIT License (MIT)
 *
 * ==---------------------------------------------------------------------------------==
 *
 *	The MIT License (MIT)
 *	Copyright (c) 2016 ALEXIS AUBRY RADANOVIC
 *
 *	Permission is hereby granted, free of charge, to any person obtaining a copy of
 *	this software and associated documentation files (the "Software"), to deal in
 *	the Software without restriction, including without limitation the rights to
 *	use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 *	the Software, and to permit persons to whom the Software is furnished to do so,
 *	subject to the following conditions:
 *
 *	The above copyright notice and this permission notice shall be included in all
 *	copies or substantial portions of the Software.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 *	FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 *	COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 *	IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ==---------------------------------------------------------------------------------==
 */

import Foundation
import CLibreSSL
import CryptoLoader
import BytesKit
@_exported import Hash
@_exported import CryptoError

// MARK: - Signature

///
/// Creates the signature of some bytes using a key and a hashing algorithm.
///
/// - parameter message: The bytes to sign.
/// - parameter key: The key to use to generate the signature.
/// - parameter hashingAlgorithm: The hashing algorithm to use to generate the signature.
///
/// - throws: In case of a failure, this function throws a `CryptoError` object.
///
/// - returns: A `Data` object containing the bytes of the signature.
///

public func sign<T: CKeyContainer>(message: Array<UInt8>, with key: T, using hashingAlgorithm: HashingAlgorithm) throws -> Data {
    
    CryptoLoader.load(.digests, .ciphers, .cryptoErrorStrings)
    
    /* Pointers */
    
    guard let messageDigest = hashingAlgorithm.messageDigest else {
        throw CryptoError.latest()
    }
    
    guard let context = EVP_MD_CTX_create() else {
        throw CryptoError.latest()
    }
    
    defer {
        EVP_MD_CTX_destroy(context)
    }
    
    /* Operation */
    
    guard EVP_DigestSignInit(context, nil, messageDigest, nil, key.underlyingKeyPointer) == 1 else {
        throw CryptoError.latest()
    }
    
    guard EVP_DigestUpdate(context, UnsafeRawPointer(message), message.count) == 1 else {
        throw CryptoError.latest()
    }
    
    /* Final */
    
    var signatureLength = 0
    
    guard EVP_DigestSignFinal(context, nil, &signatureLength) == 1 else {
        throw CryptoError.latest()
    }
    
    var signature = Array<UInt8>(repeating: 0, count: signatureLength)
    
    guard EVP_DigestSignFinal(context, &signature, &signatureLength) == 1 else {
        throw CryptoError.latest()
    }
    
    let signatureBytes = signature.prefix(upTo: signatureLength)
    return Data(bytes: signatureBytes)
    
}

///
/// Creates the signature of some bytes using a key and a hashing algorithm.
///
/// - parameter message: An object containing bytes to sign.
/// - parameter key: The key to use to generate the signature.
/// - parameter hashingAlgorithm: The hashing algorithm to use to generate the signature.
///
/// - throws: In case of a failure, this function throws a `CryptoError` object.
///
/// - returns: A `Data` object containing the bytes of the signature.
///

public func sign<T: BytesConvertible, U: CKeyContainer>(message: T, with key: U, using hashingAlgorithm: HashingAlgorithm) throws -> Data {
    return try Signature.sign(message: message.bytes, with: key, using: hashingAlgorithm)
}

// MARK: - Verification

///
/// Validates that a given signature is valid for a key and expected message.
///
/// - parameter signature: The signature to verify.
/// - parameter expectedMessage: The message that must have produced the signature.
/// - parameter key: The key that must have produced the signature (or its public counterpart).
/// - parameter hashingAlgorithm: The hashing algorithm that must have been used to produce the signature.
///
/// - throws: In case of a failure, this function throws a `CryptoError` object.
///
/// - returns: A Boolean indicating whether the signature is valid or not.
///

public func verify<T: CKeyContainer>(signature: Array<UInt8>, expectedMessage: Array<UInt8>, key: T , hashingAlgorithm: HashingAlgorithm) throws -> Bool {
    
    CryptoLoader.load(.digests, .ciphers, .cryptoErrorStrings)
    
    switch T.verificationMode {
        
    case .computation:
        return try Signature.compare(signature: signature, key: key, message: expectedMessage, hashingAlgorithm: hashingAlgorithm)
    
    case .validation:
        return try Signature.validate(signature: signature, key: key, message: expectedMessage, hashingAlgorithm: hashingAlgorithm)
        
    }
    
}

///
/// Validates that a given signature is valid for a key and expected message.
///
/// - parameter signature: The signature to verify.
/// - parameter expectedMessage: The message that must have produced the signature.
/// - parameter key: The key that must have produced the signature (or its public counterpart).
/// - parameter hashingAlgorithm: The hashing algorithm that must have been used to produce the signature.
///
/// - throws: In case of a failure, this function throws a `CryptoError` object.
///
/// - returns: A Boolean indicating whether the signature is valid or not.
///

public func verify<T: BytesConvertible, U: BytesConvertible, V: CKeyContainer>(signature: T, expectedMessage: U, key: V , hashingAlgorithm: HashingAlgorithm) throws -> Bool {
    return try Signature.verify(signature: signature.bytes, expectedMessage: expectedMessage.bytes, key: key, hashingAlgorithm: hashingAlgorithm)
}

///
/// Computes the signature of a message and compares it with a specified signature.
///
/// This function is used to validate HMAC signatures.
///
/// - parameter signature: The signature to compare.
/// - parameter expectedMessage: The message that must have produced the signature.
/// - parameter key: The key that must have produced the signature.
/// - parameter hashingAlgorithm: The hashing algorithm that must have been used to produce the signature.
///
/// - throws: In case of a failure, this function throws a `CryptoError` object.
///
/// - returns: A Boolean indicating whether the signature is valid or not.
///

private func compare<T: CKeyContainer>(signature: Array<UInt8>, key: T, message: Array<UInt8>, hashingAlgorithm: HashingAlgorithm) throws -> Bool {
    
    let expectedSignatureBytes = try Signature.sign(message: message, with: key, using: hashingAlgorithm).bytes
    return signature == expectedSignatureBytes
    
}

///
/// Validate a signature with a key and an expected message.
///
/// This function is used to validate PKI-based signatures.
///
/// - parameter signature: The signature to validate.
/// - parameter expectedMessage: The message that must have produced the signature.
/// - parameter key: The key that must have produced the signature.
/// - parameter hashingAlgorithm: The hashing algorithm that must have been used to produce the signature.
///
/// - throws: In case of a failure, this function throws a `CryptoError` object.
///
/// - returns: A Boolean indicating whether the signature is valid or not.
///

private func validate<T: CKeyContainer>(signature: Array<UInt8>, key: T, message: Array<UInt8>, hashingAlgorithm: HashingAlgorithm) throws -> Bool {
    
    /* Properties */
    
    var mutableSignature = signature
    
    /* Pointers */
    
    guard let messageDigest = hashingAlgorithm.messageDigest else {
        throw CryptoError.latest()
    }
    
    guard let context = EVP_MD_CTX_create() else {
        throw CryptoError.latest()
    }
    
    defer {
        EVP_MD_CTX_destroy(context)
    }
    
    /* Operation */
    
    guard EVP_DigestVerifyInit(context, nil, messageDigest, nil, key.underlyingKeyPointer) == 1 else {
        throw CryptoError.latest()
    }
    
    guard EVP_DigestUpdate(context, UnsafeRawPointer(message), message.count) == 1 else {
        throw CryptoError.latest()
    }
    
    /* Final */
    
    return EVP_DigestVerifyFinal(context, &mutableSignature, signature.count) == 1
    
}
