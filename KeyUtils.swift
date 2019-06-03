//
//  KeyUtils.swift
//  eoswallet
//
//  Created by Guru on 10/08/2018.
//  Copyright © 2019 Kibisis GmbH. All rights reserved.
//

import Foundation

struct KeyUtils {
    
    /**
     - Parameter key: Data
     - Parameter keyType: String - sha256x2, K1, etc
     - Returns: encoded base58 string
     */
    static func checkEncode(key: Data, keyType: String? = nil) -> String? {
        if keyType == "sha256x2" {
            let checkSum = key.sha256().sha256().prefix(4)
            let buffer = key + checkSum
            return buffer.bytes.base58EncodedString
        } else {
            var check = key
            if let keyType = keyType {
                guard let data = keyType.data(using: .utf8) else { return nil }
                check = check + data
            }
            let checksum = RIPEMD160.hash(message: check).prefix(4)
            return (key + checksum).bytes.base58EncodedString
        }
    }
    
    static func checkDecode(keyString: String) -> Data? {
        guard let buffer = keyString.base58DecodedData else { return nil }
        if buffer.count < 4 { return nil }
        let checkSum = Array(buffer[(buffer.count - 4)...])
        let key = Array(buffer[..<(buffer.count - 4)])
        if Array(key.sha256().sha256().prefix(4)) != checkSum {
            return nil
        }
        return Data(bytes: key)
    }
}

func toByteArray<T>(_ value: T) -> [UInt8] {
    var value = value
    return withUnsafeBytes(of: &value) { Array($0) }
}
