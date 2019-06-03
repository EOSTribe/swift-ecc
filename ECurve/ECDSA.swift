//
//  ECDSA.swift
//  eoswallet
//
//  Created by Jacob Roscoe on 8/27/18.
//  Copyright © 2019 Kibisis GmbH. All rights reserved.
//

import Foundation
import Security
import BigInt
import CryptoSwift

final class ECDSA {
    
    static func sign(curve: ECurve, hash: Data, d: BigInt, nonce: Int) -> ECSignature {
        
        let e = BigInt.from(hash)
        let n = curve.n, G = curve.G
        
        var r, s: BigInt!
        _ = ECDSA.deterministicGenerateK(curve: curve, hash: hash, d: d, checkSig: { (k: BigInt) -> Bool in
            let Q = G.multiply(k)
            if (curve.isInfinity(Q)) {
                return false
            }
            
            r = Q.affineX % n
            if (r.signum() == 0) {
                return false
            }
            
            s = (k.inverse(n)! * (e + (d * r))) % n
            if (s.signum() == 0) {
                return false
            }
            
            return true
        }, nonce: nonce)
        
        let N_OVER_TWO = n &>> 1
        
        // enforce low S values, see bip62: 'low s values in signatures'
        if (s > N_OVER_TWO) {
            s = n - s
        }
        return ECSignature(r, s);
    }
    
    static func deterministicGenerateK(curve: ECurve, hash: Data, d: BigInt, checkSig: (_ t: BigInt) -> Bool, nonce: Int) -> BigInt {
    
        var hash = hash
        if nonce > 0 {
            hash = (hash + Data(count: nonce)).sha256()
        }
        var x = d.to(size: 32)
        var k = Data(bytes: [UInt8].init(repeating: 0, count: 32))
        var v = Data(bytes: [UInt8].init(repeating: 1, count: 32))
        
        func hmacSHA256 (_ message: Data, with key: Data) -> Data {
            var buffer = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
            
            buffer.write(withPointerTo: message, key) { bufferPtr, messageBytes, keyBytes in
                
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                       UnsafeRawPointer(keyBytes),
                       key.count,
                       UnsafeRawPointer(messageBytes),
                       message.count,
                       UnsafeMutableRawPointer(bufferPtr))
                
            }
            
            return buffer
        }
        
        // Step D
        let data = v + Data(bytes: [0]) + x + hash
        k = hmacSHA256(data, with: k)
        
        // Step E
        v = hmacSHA256(v, with: k)
        
        // Step F
        k = hmacSHA256(v + Data(bytes: [1]) + x + hash, with: k)
        
        // Step G
        v = hmacSHA256(v, with: k)
        
        // Step H1/H2a, ignored as tlen === qlen (256 bit)
        // Step H2b
        v = hmacSHA256(v, with: k)
        
        var T = BigInt.from(v)
        // Step H3, repeat until T is within the interval [1, n - 1]
        while (T.signum() <= 0 || T >= curve.n || !checkSig(T)) {
            k = hmacSHA256(v + Data(bytes: [0]), with: k)
            v = hmacSHA256(v, with: k)
            
            // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
            // Step H2b again
            v = hmacSHA256(v, with: k)
            T = BigInt.from(v)
        }
        
        return T
    }
    
    /**
     * Recover a public key from a signature.
     *
     * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
     * Key Recovery Operation".
     *
     * http://www.secg.org/download/aid-780/sec1-v2.pdf
     */
    static func recoverPubKey(curve: ECurve, e: BigInt, signature: ECSignature, i: Int) -> ECPoint {
        assert(i & 3 == i, "Recovery param is more than two bits")
        let n = curve.n;
        let G = curve.G;
    
        let r = signature.r;
        let s = signature.s;
    
//        assert(r.signum() > 0 && r.compareTo(n) < 0, "Invalid r value")
//        assert(s.signum() > 0 && s.compareTo(n) < 0, "Invalid s value")
    
        // A set LSB signifies that the y-coordinate is odd
        let isYOdd = (i & 1 == 1)
    
        // The more significant bit specifies whether we should use the
        // first or second candidate key.
        let isSecondKey = i >> 1
    
        // 1.1 Let x = r + jn
        let x = (isSecondKey == 1) ? (r + n) : r
        let R = curve.pointFromX(isYOdd, x)
    
        // 1.4 Check that nR is at infinity
//        let nR = R.multiply(n)
//        assert(curve.isInfinity(nR), "nR is not a valid curve point")
    
        // Compute -e from e
        let e = e.negate()
        let eNeg = e % n
    
        // 1.6.1 Compute Q = r^-1 (sR -  eG)
        //               Q = r^-1 (sR + -eG)
        let rInv = r.inverse(n)!
    
        let Q = R.multiplyTwo(s, G, eNeg).multiply(rInv)
//        if !curve.validate(Q) {
//            print("Invalid public key")
//        }
    
        return Q;
    }
    
    /**
     * Calculate pubkey extraction parameter.
     *
     * When extracting a pubkey from a signature, we have to
     * distinguish four different cases. Rather than putting this
     * burden on the verifier, Bitcoin includes a 2-bit value with the
     * signature.
     *
     * This function simply tries all four cases and returns the value
     * that resulted in a successful pubkey recovery.
     */
    static func calcPubKeyRecoveryParam(curve: ECurve, e: BigInt, signature: ECSignature, Q: ECPoint) -> Int {

        var Qprime: ECPoint
        for i in 0..<4 {
            Qprime = ECDSA.recoverPubKey(curve: curve, e: e, signature: signature, i: i)
            if Qprime.equalsTo(Q) {
                return i
            }
        }
        
        print("Unable to find valid recovery factor")
        return 0
    }
}
