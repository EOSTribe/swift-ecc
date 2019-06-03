//
//  ECurve.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.

import BigInt
import Foundation

public class ECurve {
    
    // let G: ECPoint // ECPoint refers to an ECurve, so this would create a cycle
    public let gX: BigInt
    public let gY: BigInt
    
    public let p: BigInt
    public let a: BigInt
    public let b: BigInt
    
    public let n: BigInt
    public let h: BigInt?
    
    init(_ p: BigInt, _ a: BigInt, _ b: BigInt, gX: BigInt, gY: BigInt, n: BigInt, h: BigInt) {
        self.p = p
        self.a = a
        self.b = b
        self.gX = gX
        self.gY = gY
        self.n = n
        self.h = h
    }
    
    public var G: ECPoint {
        return ECPoint(curve: self, x: gX, y: gY, z: BigInt(1))
    }
    
    public func isInfinity(_ Q: ECPoint) -> Bool {
        if Q === self.infinity {
            return true
        }
        if Q.y == nil || Q.z == nil {
            return true
        } else {
            return ((Q.z!.signum() == 0) && (Q.y!.signum() != 0))
        }
    }
    
    public var infinity: ECPoint {
        return ECPoint(curve: self, x: nil, y: nil, z: BigInt(0))
    }
    
    public func pointFromX(_ isOdd: Bool, _ x: BigInt) -> ECPoint {
        let alpha = ((x.power(3) + a * x) + b) % p
        let pOverFour = (p + BigInt(1)) &>> 2
        let beta = alpha.power(pOverFour, modulus: p)
        
        var y = beta
        let isEven = (y.toByteArray()[0] == 0)
        if isEven == isOdd {
            y = self.p - y
        }
        
        return ECPoint.fromAffine(curve: self, x: x, y: y)
    }
    
    public func validate(_ Q: ECPoint) -> Bool {
//        assert(!isInfinity(Q), "Point is at infinity")
//        assert(isOnCurve(Q), "Point is not on the curve")
        
        let nQ = Q.multiply(self.n)
        assert(self.isInfinity(nQ), "Point is not a scalar multiple of G")
        
        return true
    }
}
