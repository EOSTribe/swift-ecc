//
//  PublicKey.swift
//  eoswallet
//
//  Created by Jacob Roscoe on 8/29/18.
//  Copyright © 2019 Kibisis GmbH. All rights reserved.
//

import Foundation

final class PublicKey {
    
    public let data: Data
    
    var Q: ECPoint {
        return ECPoint.decodeFrom(Signature.curve, data)
    }
    
    public var isCompressed: Bool {
        let header = data[0]
        return (header == 0x02 || header == 0x03)
    }
    
    init(_ data: Data) {
        self.data = data
    }
    
    /** toStringLegacy
     - Parameter pubkey_prefix: public key prefix.
     */
    public func toString(pubkey_prefix: String = "EOS") -> String {
        
        return pubkey_prefix + (KeyUtils.checkEncode(key: data) ?? "")
    }
}
