/*
 * ==---------------------------------------------------------------------------------==
 *
 *  File            :   RSATests.swift
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
import Signature

///
/// A set of tests to test the RSA signature and verification API.
///

class RSATests: XCTestCase {

    // MARK: - RSA Tests
    
    ///
    /// Tests RSA with MD4.
    ///
    
    func testRMD4() {
        
        testRSA(testVectors: rsa1024withMD4TestVectors)
        testRSA(testVectors: rsa2048withMD4TestVectors)
        
        testRSA(testVectors: rsa1024withMD4FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withMD4FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with MD5.
    ///
    
    func testRMD5() {

        testRSA(testVectors: rsa1024withMD5TestVectors)
        testRSA(testVectors: rsa2048withMD5TestVectors)
        
        testRSA(testVectors: rsa1024withMD5FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withMD5FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with SHA1.
    ///
    
    func testRS1() {
        
        testRSA(testVectors: rsa1024withSHA1TestVectors)
        testRSA(testVectors: rsa2048withSHA1TestVectors)
        
        testRSA(testVectors: rsa1024withSHA1FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withSHA1FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with SHA224.
    ///
    
    func testRS224() {
        
        testRSA(testVectors: rsa1024withSHA224TestVectors)
        testRSA(testVectors: rsa2048withSHA224TestVectors)
        
        testRSA(testVectors: rsa1024withSHA224FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withSHA224FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with SHA256.
    ///
    
    func testRS256() {
        
        testRSA(testVectors: rsa1024withSHA256TestVectors)
        testRSA(testVectors: rsa2048withSHA256TestVectors)
        
        testRSA(testVectors: rsa1024withSHA256FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withSHA256FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with SHA384.
    ///
    
    func testRS384() {
        
        testRSA(testVectors: rsa1024withSHA384TestVectors)
        testRSA(testVectors: rsa2048withSHA384TestVectors)
        
        testRSA(testVectors: rsa1024withSHA384FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withSHA384FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with SHA512.
    ///
    
    func testRS512() {
        
        testRSA(testVectors: rsa1024withSHA512TestVectors)
        testRSA(testVectors: rsa2048withSHA512TestVectors)
        
        testRSA(testVectors: rsa1024withSHA512FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withSHA512FakeTestVectors, isFake: true)
        
    }
    
    ///
    /// Tests RSA with RIPEMD160.
    ///
    
    func testRRMD160() {

        testRSA(testVectors: rsa1024withRIPEMD160TestVectors)
        testRSA(testVectors: rsa2048withRIPEMD160TestVectors)
        
        testRSA(testVectors: rsa1024withRIPEMD160FakeTestVectors, isFake: true)
        testRSA(testVectors: rsa2048withRIPEMD160FakeTestVectors, isFake: true)
        
    }
    
    // MARK: - RSA Helpers
    
    ///
    /// Runs the RSA testing algorithm against a list of test vectors.
    ///
    /// - parameter testVectors: The tests vectors to use to perform the tests.
    /// - parameter isFake: A Boolean indicating whether the tests vectors are fake (with wrong signatures), or not. Defaults to false.
    ///
    
    func testRSA(testVectors: Array<RSATestVector>, isFake: Bool = false) {
        
        let successRequirement = isFake ? false : true
        
        for vector in testVectors {
            
            guard let publicKeyPath = TestsManager.path(ofKey: vector.publicKeyName), let privateKeyPath = TestsManager.path(ofKey: vector.privateKeyName) else {
                XCTFail("Cannot find keys.")
                return
            }
            
            do {
                
                // 1. Load the keys
                
                let publicKey = try CryptoKey(path: publicKeyPath, component: .publicKey)
                let privateKey = try CryptoKey(path: privateKeyPath, component: .privateKey(passphrase: vector.privateKeyPassphrase))
                
                // 2. Compute the signature of the message
                
                let signature = try Signature.sign(message: vector.message.bytes, with: privateKey, using: vector.algorithm)
                
                // 3. Assert that the computed signature is valid
                
                let isSignatureValid = try Signature.verify(signature: signature.bytes, expectedMessage: vector.message.bytes, key: publicKey, hashingAlgorithm: vector.algorithm)
                
                XCTAssertTrue(isSignatureValid)
                
                // 4. Verify that the library recognizes valid and invalid signatures
                
                let verificationResult = try Signature.verify(signature: Data(hexString: vector.expectedSignatureHex)!.bytes, expectedMessage: vector.message.bytes, key: publicKey, hashingAlgorithm: vector.algorithm)
                
                XCTAssertTrue(verificationResult == successRequirement)
                
                // 5. Verify that the signature is equal to the expected signature (or not equal if the test vector is fake)
                
                XCTAssertTrue((signature.hexString == vector.expectedSignatureHex) == successRequirement)
                
            } catch {
                dump(error)
                XCTFail("Unexpected error : \(error)")
            }
            
        }
    
    }
    
}

extension RSATests {
    
    ///
    /// All the tests to run on Linux.
    ///
    
    static var allTests : [(String, (RSATests) -> () throws -> Void)] {
        return [
            ("testRMD4", testRMD4),
            ("testRMD5", testRMD5),
            ("testRS1", testRS1),
            ("testRS224", testRS224),
            ("testRS256", testRS256),
            ("testRS384", testRS384),
            ("testRS512", testRS512),
            ("testRRMD160", testRRMD160),
        ]
    }
    
}
