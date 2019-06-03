//
//  PrivateKey.swift
//  eoswallet
//
//  Created by Jacob Roscoe on 8/23/18.
//  Copyright © 2019 Kibisis GmbH. All rights reserved.
//

import Foundation
import BigInt
import CryptoSwift

extension String {
    func parseWif() -> Data? {
        return KeyUtils.checkDecode(keyString: self)
    }
}

final class PrivateKey {
    
    public var data: Data
    public var publicKey: PublicKey?
    
    public var bigi: BigInt {
        return BigInt(BigUInt(data))
    }
    
    init(_ data: Data) {
        self.data = data
    }

    /**
     - Returns: Random PrivateKey
     */
    static func randomKey() -> PrivateKey? {
        if let randomKeyData = SECP256K1.generatePrivateKey() {
            return PrivateKey(randomKeyData)
        } else {
            return nil
        }
    }
    
    /**
     - Parameter seed: any length string.  This is private, the same seed produces the same private key every time.
     - Returns: PrivateKey
     */
    static func fromSeed(_ seed: String) -> PrivateKey? {
        let data = seed.data(using: .utf8)!.sha256()
        return PrivateKey.fromData(data)
    }
    
    static func fromWif(_ keyString: String) -> PrivateKey? {
        guard let data = keyString.parseWif() else {
            return nil
        }
        return PrivateKey.fromData(data.dropFirst())
    }
    
    static func fromData(_ data: Data) -> PrivateKey? {
        var data = data
        
        if data.count == 33 && data[32] == 1 {
            data = data.dropLast()
        }
        if data.count == 32 {
            if data.first == 0x80 {
                var data = data
                data.insert(0x00, at: 0)
            }
            return PrivateKey(data)
        } else {
            return nil
        }
    }
    
    /**
     - Returns: {string} private key like PVT_K1_base58privatekey..
     */
    public func toString() -> String? {
        // todo, use PVT_K1_
        // return 'PVT_K1_' + keyUtils.checkEncode(toBuffer(), 'K1')
        return toWif()
    }
    
    private func toWif() -> String? {
        var privateKey = bigi.to(size: 32)
        privateKey = Data(bytes: [0x80]) + privateKey
        return KeyUtils.checkEncode(key: privateKey, keyType: "sha256x2")
    }
    
    /**
     - Returns:  Public Key
     */
    func toPublic() -> PublicKey? {
        if let publicKey = self.publicKey {
            return publicKey
        }
        
        guard let data = SECP256K1.privateToPublic(privateKey: self.data, compressed: true) else { return nil }
        self.publicKey = PublicKey(data)
        
        return self.publicKey
    }
}
