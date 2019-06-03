//
//  Signature.swift
//  eoswallet
//
//  Created by Jacob Roscoe on 10/08/2018.
//  Copyright © 2019 Kibisis GmbH. All rights reserved.
//

import Foundation
import BigInt

final public class Signature {

    public var r: BigInt
    public var s: BigInt
    public var i: Int
    
    // https://github.com/cryptocoinjs/ecurve/blob/master/lib/curves.json
    static let curve = ECurve(BigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", radix: 16)!,
                              BigInt("00", radix: 16)!,
                              BigInt("07", radix: 16)!,
                               gX: BigInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", radix: 16)!,
                               gY: BigInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", radix: 16)!,
                               n: BigInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", radix: 16)!,
                               h: BigInt("01", radix: 16)!)
    
    init(r: BigInt, s: BigInt, i: Int) {
        self.r = r
        self.s = s
        self.i = i
    }
    
    /**
     Create a signature using a hash.
     - Parameter message: String
     - Parameter privateKey: PrivateKey
     - Parameter encoding: String.Encoding
     
     - Returns: Signature
        Examples: ecc.sign('I am alive', wif)
     */
    static func sign(data: Data, privateKey: PrivateKey, encoding: String.Encoding = .utf8) -> Signature? {
        let dataSha256 = data.sha256()
        
        var i: Int = 0
        var nonce = 0
        let e = BigInt.from(dataSha256)
        let Q = Signature.curve.G.multiply(privateKey.bigi)
        
        var ecSignature: ECSignature!
        while (true) {
            ecSignature = ECDSA.sign(curve: Signature.curve, hash: dataSha256, d: privateKey.bigi, nonce: nonce)
            
            let der = ecSignature.toDer()
            let lenR = der[3], lenS = der[5 + Int(lenR)]
            if lenR == 32 && lenS == 32 {
                i = ECDSA.calcPubKeyRecoveryParam(curve: Signature.curve, e: e, signature: ecSignature, Q: Q)
                i += 4 // compressed
                i += 27 // compact
                break;
            }
            
            nonce += 1
            if nonce % 10 == 0 {
                print("WARN: " + "\(nonce)" + " attempts to find canonical signature")
            }
        }
        
        return Signature(r: ecSignature.r, s: ecSignature.s, i: i)
    }
    
    /** toStringLegacy
     - Parameter pubkey_prefix: public key prefix.
     */
    public func toString() -> String {
        return "SIG_K1_" + (KeyUtils.checkEncode(key: toData(), keyType: "K1") ?? "")
    }
    
    private func toData() -> Data {
        var buf = Data(count: 65)
        buf[0] = UInt8(i)
        buf[1..<33] = r.to(size: 32)
        buf[33..<65] = s.to(size: 32)
        return buf
    }
    
    static func getSignature(data: Data) -> Data? {
        guard let unmarshalledSignature = SECP256K1.unmarshalSignature(signatureData: data) else { return nil }
        let marshalledSignature = SECP256K1.marshalSignature(v: unmarshalledSignature.v, r: unmarshalledSignature.r, s: unmarshalledSignature.s)
        return marshalledSignature ?? nil
    }
}
