/*
 * ==---------------------------------------------------------------------------------==
 *
 *  File            :   HMACTests.swift
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

import XCTest
import Foundation
@testable import Signature

///
/// A set of tests to test the HMAC signature and verification API.
///

class HMACTests: XCTestCase {
    
    // MARK: - HMAC Tests
    
    ///
    /// Tests HMAC with MD4.
    ///
    
    func testHMD4() {
        testHMAC(testVectors: hmd4TestVectors)
        testHMAC(testVectors: hmd4FakeTestVectors, isFake: true)
    }
    
    ///
    /// Tests HMAC with MD5.
    ///
    
    func testHMD5() {
        testHMAC(testVectors: hmd5TestVectors)
        testHMAC(testVectors: hmd5FakeTestVectors, isFake: true)
    }
    
    ///
    /// Tests HMAC with SHA1.
    ///
    
    func testHS1() {
        testHMAC(testVectors: hs1TestVectors)
        testHMAC(testVectors: hs1FakeTestVectors, isFake: true)
    }
    
    ///
    /// Tests HMAC with SHA224.
    ///
    
    func testHS224() {
        testHMAC(testVectors: hs224TestVectors)
        testHMAC(testVectors: hs224FakeTestVectors, isFake: true)
    }
    
    ///
    /// Tests HMAC with SHA256.
    ///
    
    func testHS256() {
        testHMAC(testVectors: hs256TestVectors)
        testHMAC(testVectors: hs256FakeTestVectors, isFake: true)
    }
    
    ///
    /// Tests HMAC with SHA384.
    ///
    
    func testHS384() {
        testHMAC(testVectors: hs384TestVectors)
        testHMAC(testVectors: hs384FakeTestVectors, isFake: true)
    }
    
    ///
    /// Tests HMAC with SHA512.
    ///
    
    func testHS512() {
        testHMAC(testVectors: hs512TestVectors)
        testHMAC(testVectors: hs512FakeTestVectors, isFake: true)
    }

    ///
    /// Tests HMAC with RIPEMD-160.
    ///
    
    func testHRMD160() {
        testHMAC(testVectors: hrmd160TestVectors)
        testHMAC(testVectors: hrmd160FakeTestVectors, isFake: true)
    }
    
    // MARK: - HMAC Helpers
    
    ///
    /// Runs the HMAC testing algorithm against a list of test vectors.
    ///
    /// - parameter testVectors: The tests vectors to use to perform the tests.
    /// - parameter isFake: A Boolean indicating whether the tests vectors are fake (with wrong signatures), or not. Defaults to false.
    ///
    
    func testHMAC(testVectors: Array<HMACTestVector>, isFake: Bool = false) {
        
        let successRequirement = isFake ? false : true
        
        for vector in testVectors {
            
            do {
                
                // 1. Create the key with the passphrase in the vector
                
                let hmacKey = try HMACKey(password: vector.keyPassword)
                
                // 2. Sign the message with the key
                
                let signature = try Signature.sign(message: vector.message.bytes, with: hmacKey, using: vector.algorithm)
                
                // 3. Verify that the generated signature is valid
                
                let isSignatureValid = try Signature.verify(signature: signature.bytes, expectedMessage: vector.message.bytes, key: hmacKey, hashingAlgorithm: vector.algorithm)
                
                XCTAssertTrue(isSignatureValid)
                
                // 4. Verify that the library recognizes valid and invalid signatures
                
                let verificationResult = try Signature.verify(signature: Data(hexString: vector.expectedSignatureHex)!.bytes, expectedMessage: vector.message.bytes, key: hmacKey, hashingAlgorithm: vector.algorithm)
                
                XCTAssertTrue(verificationResult == successRequirement)
                
                // 5. Verify that the signature is equal to the expected signature (or not equal if the test vector is fake)
                
                XCTAssertTrue((signature.hexString == vector.expectedSignatureHex) == successRequirement)
                
            } catch {
                dump(error)
                XCTFail("An error occured : \(error)")
            }
            
        }
        
    }
    
}

extension HMACTests {
    
    ///
    /// All the tests to run on Linux.
    ///
    
    static var allTests : [(String, (HMACTests) -> () throws -> Void)] {
        return [
            ("testHMD4", testHMD4),
            ("testHMD5", testHMD5),
            ("testHS1", testHS1),
            ("testHS224", testHS224),
            ("testHS256", testHS256),
            ("testHS384", testHS384),
            ("testHS512", testHS512),
            ("testHRMD160", testHRMD160),
        ]
    }
    
}
