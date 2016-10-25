/*
 * ==---------------------------------------------------------------------------------==
 *
 *  File            :   ECDSATests.swift
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
/// A set of tests to test the signature and verification API with ECDSA.
///

class ECDSATests: XCTestCase {
    
    // MARK: - ECDSA Tests
    
    ///
    /// Tests ECDSA with SHA1.
    ///
    
    func testES1() {
        
        testECDSA(testVectors: ecdsaP256withSHA1TestVectors)
        testECDSA(testVectors: ecdsaP384withSHA1TestVectors)
        testECDSA(testVectors: ecdsaSECP256K1withSHA1TestVectors)
        
        testECDSA(testVectors: ecdsaFakeP256withSHA1TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeP384withSHA1TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeSECP256K1withSHA1TestVectors, isFake: true)
        
    }
    
    ///
    /// Tests ECDSA with SHA224.
    ///
    
    func testES224() {
        
        testECDSA(testVectors: ecdsaP256withSHA224TestVectors)
        testECDSA(testVectors: ecdsaP384withSHA224TestVectors)
        testECDSA(testVectors: ecdsaSECP256K1withSHA224TestVectors)
        
        testECDSA(testVectors: ecdsaFakeP256withSHA224TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeP384withSHA224TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeSECP256K1withSHA224TestVectors, isFake: true)
        
    }
    
    ///
    /// Tests ECDSA with SHA256.
    ///
    
    func testES256() {
        
        testECDSA(testVectors: ecdsaP256withSHA256TestVectors)
        testECDSA(testVectors: ecdsaP384withSHA256TestVectors)
        testECDSA(testVectors: ecdsaSECP256K1withSHA256TestVectors)
        
        testECDSA(testVectors: ecdsaFakeP256withSHA256TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeP384withSHA256TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeSECP256K1withSHA256TestVectors, isFake: true)
        
    }
    
    ///
    /// Tests ECDSA with SHA384.
    ///
    
    func testES384() {
        
        testECDSA(testVectors: ecdsaP256withSHA384TestVectors)
        testECDSA(testVectors: ecdsaP384withSHA384TestVectors)
        testECDSA(testVectors: ecdsaSECP256K1withSHA384TestVectors)
        
        testECDSA(testVectors: ecdsaFakeP256withSHA384TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeP384withSHA384TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeSECP256K1withSHA384TestVectors, isFake: true)
        
    }
    
    ///
    /// Tests ECDSA with SHA512.
    ///
    
    func testES512() {
        
        testECDSA(testVectors: ecdsaP256withSHA512TestVectors)
        testECDSA(testVectors: ecdsaP384withSHA512TestVectors)
        testECDSA(testVectors: ecdsaSECP256K1withSHA512TestVectors)
        
        testECDSA(testVectors: ecdsaFakeP256withSHA512TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeP384withSHA512TestVectors, isFake: true)
        testECDSA(testVectors: ecdsaFakeSECP256K1withSHA512TestVectors, isFake: true)
        
    }
    
    // MARK: - ECDSA Helpers
    
    ///
    /// Runs the ECDSA testing algorithm against a list of test vectors.
    ///
    /// - parameter testVectors: The tests vectors to use to perform the tests.
    /// - parameter isFake: A Boolean indicating whether the tests vectors are fake (with wrong signatures), or not. Defaults to false.
    ///
    
    func testECDSA(testVectors: Array<ECDSATestVector>, isFake: Bool = false) {
        
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
                
                let verificationResult = try Signature.verify(signature: Data(hexString: vector.validSignature)!.bytes, expectedMessage: vector.message.bytes, key: publicKey, hashingAlgorithm: vector.algorithm)
                
                XCTAssertTrue(verificationResult == successRequirement)
                                
            } catch {
                dump(error)
                XCTFail("Unexpected error : \(error)")
            }
            
        }
        
    }
        
}

extension ECDSATests {
    
    ///
    /// All the tests to run on Linux.
    ///
    
    static var allTests : [(String, (ECDSATests) -> () throws -> Void)] {
        return [
            ("testES1", testES1),
            ("testES224", testES224),
            ("testES256", testES256),
            ("testES384", testES384),
            ("testES512", testES512)
        ]
    }
    
}
