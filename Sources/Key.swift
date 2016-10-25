/*
 * ==---------------------------------------------------------------------------------==
 *
 *  File            :   Key.swift
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
@_exported import Hash
@_exported import CryptoError

// MARK: - Protocols

///
/// A set of requirements for class objects that can contain C EVP keys.
///
/// You don't conform to this protocol yourself. Instead, use either `HMACKey` or `CryptoKey`.
///

public protocol CKeyContainer: class {
    
    ///
    /// Describes how signatures created with keys of this type must be validated.
    ///
    /// - seealso: KeyVerificationMode
    ///
    
    static var verificationMode: KeyVerificationMode { get }
    
    ///
    /// The pointer to the C EVP key contained by the receiver.
    ///
    
    var underlyingKeyPointer: UnsafeMutablePointer<EVP_PKEY> { get }
}

///
/// An enumeration of signature verification methods.
///

public enum KeyVerificationMode {
    
    ///
    /// The signature of the expected message must be computed and compared with the signature.
    ///
    /// This method must be used for HMAC and CMAC keys.
    ///
    
    case computation
    
    ///
    /// The signature must be validated using the key itself.
    ///
    /// This method must be used for DSA, ECDSA, ECDSH and RSA keys.
    ///
    
    case validation
    
}

// MARK: - HMAC Keys

///
/// A type that contains keys to create hashed message authentication codes.
///

public class HMACKey: CKeyContainer {
    
    // MARK: - Properties
    
    public static let verificationMode = KeyVerificationMode.computation
    
    public let underlyingKeyPointer: UnsafeMutablePointer<EVP_PKEY>
    
    // MARK: - Lifecycle
    
    ///
    /// Create a HMAC key with the bytes composing its password.
    ///
    /// - parameter passwordBytes: The bytes composing the key's password.
    ///
    /// - throws: In case of failure, this initializer throws a `CryptoError` object.
    ///
    
    public init(passwordBytes: Array<UInt8>) throws {
        
        CryptoLoader.load(.digests, .cryptoErrorStrings)
        
        var mutablePassword = passwordBytes
        
        guard let pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nil, &mutablePassword, Int32(mutablePassword.count)) else {
            throw CryptoError.latest()
        }
        
        underlyingKeyPointer = pkey
        
    }
    
    ///
    /// Create a HMAC key with its password.
    ///
    /// - parameter password: The key's password.
    ///
    /// - throws: In case of failure, this initializer throws a `CryptoError` object.
    ///
    
    public convenience init<T: BytesConvertible>(password: T) throws {
        try self.init(passwordBytes: password.bytes)
    }
    
    deinit {
        EVP_PKEY_free(underlyingKeyPointer)
    }
    
}

// MARK: - Keys

///
/// A type that contains keys.
///

public class CryptoKey: CKeyContainer {
    
    // MARK: Types
    
    ///
    /// An enumeration of the components of keys.
    ///
    
    public enum Component {
        
        ///
        /// The public part of the key.
        ///
        
        case publicKey
        
        ///
        /// The private part of the key, optionally protected with a passphrase.
        ///
        
        case privateKey(passphrase: String?)
        
    }
    
    // MARK: - Properties

    public static let verificationMode = KeyVerificationMode.validation
    
    public let underlyingKeyPointer: UnsafeMutablePointer<EVP_PKEY>
    
    // MARK: - Lifecycle
    
    ///
    /// Create a key object using an on-disk key.
    ///
    /// - parameter path: The path to the key.
    /// - parameter component: The component of the key to load.
    ///
    /// - warning: The on-disk key must be written in the PEM format.
    ///
    
    public init(path: String, component: Component) throws {
        
        CryptoLoader.load(.digests, .ciphers, .cryptoErrorStrings)
        
        guard let bio = BIO_new_file(path, "r") else {
            throw CryptoError.latest()
        }
        
        switch component {
            
        case .publicKey:
            
            guard let pubKey = PEM_read_bio_PUBKEY(bio, nil, nil, nil) else {
                throw CryptoError.latest()
            }
            
            underlyingKeyPointer = pubKey
            
        case .privateKey(let passphrase):
            
            let passphraseBytes = passphrase?.withCString { UnsafeMutableRawPointer(mutating: $0) }
            
            guard let pkey = PEM_read_bio_PrivateKey(bio, nil, { CryptoKey.password_cb($0, $1, $2, $3) }, passphraseBytes) else {
                throw CryptoError.latest()
            }
            
            underlyingKeyPointer = pkey
            
        }
        
    }
    
    deinit {
        EVP_PKEY_free(underlyingKeyPointer)
    }

    // MARK: - Helpers
    
    ///
    /// Runs the password callback required to read private keys.
    ///
    /// - parameter buf: The pointer where the password must be copied.
    /// - parameter bufferSize: The size of the buffer.
    /// - parameter rwflag: Ignored.
    /// - parameter password: The bytes of the password.
    ///
    /// - returns: The number of bytes that have been copied to the buffer.
    ///
    
    private static func password_cb(_ buf: UnsafeMutablePointer<Int8>?, _ bufferSize: Int32, _ rwflag: Int32, _ password: UnsafeMutableRawPointer?) -> Int32 {
        
        guard buf != nil else {
            return 0
        }
        
        guard password != nil else {
            strcpy(buf!, "")
            return 0
        }
        
        let ptr = password!.assumingMemoryBound(to: Int8.self)
        
        var n = Int32(strlen(ptr))
        
        if n >= bufferSize {
            n = bufferSize - 1
        }
        
        memcpy(buf!, password!, Int(n))
        
        return n
        
    }
    
}
