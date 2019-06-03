//
//  ECSignature.swift
//  eoswallet
//
//  Created by Jacob Roscoe on 8/29/18.
//  Copyright © 2019 Kibisis GmbH. All rights reserved.
//

import Foundation
import BigInt


final class ECSignature {
    
    var r,s : BigInt
    
    init(_ r: BigInt, _ s: BigInt) {
        self.r = r
        self.s = s
    }
    
    public func toCompact(i: Int, compressed: Bool) -> Data{
        
        var i = i
        if compressed {
            i += 4
        }
        i += 27
        
        var buffer = Data(count: 65)
        buffer[0] = UInt8(i)
        buffer[1..<33] = r.to(size: 32)
        buffer[33..<65] = s.to(size: 32)
        
        return buffer
    }
    
    public func toDer() -> [Int] {
        var rBa = [Int](), sBa = [Int]()
        let rUBa = r.toByteArray()
        for (i, rr) in rUBa.enumerated() {
            var r = Int(rr)
            if rr > 128 {
                r -= 256
            }
            if i == 0 && r < 0 {
                rBa.append(0)
            }
            rBa.append(r)
        }
        let sUBa = s.toByteArray()
        for (i, ss) in sUBa.enumerated() {
            var s = Int(ss)
            if ss > 128 {
                s -= 256
            }
            if i == 0 && s < 0 {
                sBa.append(0)
            }
            sBa.append(s)
        }
        
        var sequence = [Int]()
        
        sequence.append(contentsOf: [2, rBa.count])
        sequence.append(contentsOf: rBa)
        sequence.append(contentsOf:[2, sBa.count])
        sequence.append(contentsOf: sBa)
        
        sequence.insert(contentsOf: [0x30, sequence.count], at: 0)
        
        return sequence
    }
}
