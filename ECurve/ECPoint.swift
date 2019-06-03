//
//  ECPoint.swift
//  Crypto Coin Swift
//
//  Created by Sjors Provoost on 26-06-14.

// List of methods that should be supported:
// http://cryptocoinjs.com/modules/crypto/ecurve/  (under Point)
// Use Swift style syntax where possible. E.g. not point.add(point), but point + point

import BigInt
import Foundation

let THREE = BigInt(3)

public class ECPoint {
    
    public let curve: ECurve
    public var x: BigInt?
    public var y: BigInt?
    public var z: BigInt?

    public var _zInv: BigInt?
    public var compressed: Bool
    
    init(curve: ECurve, x: BigInt?, y: BigInt?, z: BigInt? = nil) {
        
        self.curve = curve
        self.x = x
        self.y = y
        self.z = z
        self._zInv = nil
        self.compressed = true
    }
    
    var zInv: BigInt {
        if _zInv == nil {
            _zInv = z!.inverse(curve.p)//.modInverse(curve.p)
        }
        return _zInv!
    }
    
    var affineX: BigInt {
        return (x! * zInv) % curve.p
    }
    
    var affineY: BigInt {
        return (y! * zInv) % curve.p
    }
    
    static func fromAffine(curve: ECurve, x: BigInt, y: BigInt) -> ECPoint {
        return ECPoint(curve: curve, x: x, y: y, z: BigInt(1))
    }
    
    public func equalsTo(_ other: ECPoint) -> Bool {
        if other === self { return true }
        if curve.isInfinity(self) { return curve.isInfinity(other) }
        if curve.isInfinity(other) { return curve.isInfinity(self) }
        
        let u = ((other.y! * self.z!) - (self.y! * other.z!)) % curve.p
        if u.signum() !=  0 {
            return false
        }
        
        let v = ((other.x! * self.z!) - (self.x! * other.z!)) % curve.p
        
        return v.signum() == 0
    }
    
    public func negate() -> ECPoint {
        let y = curve.p - self.y!
        return ECPoint(curve: curve, x: x, y: y, z: z)
    }
    
    public func add(_ b: ECPoint) -> ECPoint {
        if curve.isInfinity(self) { return b }
        if curve.isInfinity(b) { return self }
        
        let x1 = x!, y1 = y!, x2 = b.x!, y2 = b.y!
        
        let u = ((y2 * z!) - (y1 * b.z!)) % curve.p
        let v = ((x2 * z!) - (x1 * b.z!)) % curve.p
        
        if (v.signum() == 0) {
            if u.signum() == 0 {
                return self.twice()
            }
            
            return curve.infinity
        }
        
        let v2 = v * v
        let v3 = v2 * v
        let x1v2 = x1 * v2
        let zu2 = (u * u) * z!
        
        var x3 = (((zu2 - (x1v2 &<< 1)) * b.z! - v3) * v) % curve.p
        if x3.signum() < 0 {
           x3 = x3 + curve.p
        }
        var y3 = (((((x1v2 * THREE) * u - (y1 * v3)) - (zu2 * u)) * b.z!) + (u * v3)) % curve.p
        if y3.signum() < 0 {
            y3 = y3 + curve.p
        }
        var z3 = ((v3 * z!) * b.z!) % curve.p
        if z3.signum() < 0 {
            z3 = z3 + curve.p
        }
        
        return ECPoint(curve: curve, x: x3, y: y3, z: z3)
    }
    
    public func twice() -> ECPoint {
        if curve.isInfinity(self) { return self }
        if y?.signum() == 0 { return curve.infinity }
        
        let x1 = x!, y1 = y!
        
        let y1z1 = (y1 * z!) % curve.p
        let y1sqz1 = (y1z1 * y1) % curve.p
        let a = curve.a
        
        var w = x1.power(2) * THREE
        if a.signum() != 0 {
            w = w + (z! * z! * a)
        }
        
        w = w % curve.p
        var x3 = (((w.power(2) - (x1 &<< 3) * y1sqz1) &<< 1) * y1z1) % curve.p
        if x3.signum() < 0 {
           x3 = x3 + curve.p
        }
        var y3 = ((((w * THREE * x1) - (y1sqz1 &<< 1)) &<< 2) * y1sqz1 - (w.power(3))) % curve.p
        if y3.signum() < 0 {
            y3 = y3 + curve.p
        }
        var z3 = ((y1z1.power(3)) &<< 3) % curve.p
        if z3.signum() < 0 {
            z3 = z3 + curve.p
        }
        
        return ECPoint(curve: curve, x: x3, y: y3, z: z3)
    }
    
    public func multiply(_ k: BigInt) -> ECPoint {
        
        if curve.isInfinity(self) { return self }
        if k.signum() == 0 {
            return curve.infinity
        }
        
        let e = k
        let h = e * THREE
        let neg = self.negate()
        var R = self
        let length = String(h.magnitude, radix: 2).count
        
        for i in 2..<length {
            let j = length - i
            let hBit = h.testBit(j)
            let eBit = e.testBit(j)
            R = R.twice()
            if hBit != eBit {
                R = R.add(hBit ? self : neg)
            }
        }
        
        return R
    }
    
    public func multiplyTwo(_ j: BigInt, _ x: ECPoint, _ k: BigInt) -> ECPoint {
        var i = max(j.bitWidth, k.bitWidth) - 1
        var R = curve.infinity
        let both = self.add(x)
        
        while (i >= 0) {
            let jBit = j.testBit(i), kBit = k.testBit(i)
            
            R = R.twice()
            
            if jBit {
                if kBit {
                    R = R.add(both)
                } else {
                    R = R.add(self)
                }
            } else if kBit {
                R = R.add(x)
            }
            i = i - 1
        }
        
        return R
    }
    
    public func getEncoded(_ compressed: Bool? = nil) -> Data {
        var compressed = compressed
        if compressed == nil {
            compressed = self.compressed
        }
        if curve.isInfinity(self) {
            return Data.init(bytes: [0x00])
        }
        
        let x = self.affineX, y = self.affineY
        let byteLength = (curve.p.bitWidth + 7) / 8
        var buffer: Data!
        
        if compressed! {
            buffer = Data(count: 1 + byteLength)
            let isEven = (y.toByteArray()[0] == 0)
            buffer[0] = isEven ? 0x02 : 0x03
        } else {
            buffer = Data(count: byteLength * 2 + 1)
            buffer[0] = 0x04
            buffer[(1 + byteLength)..<(buffer.count)] = y.to(size: byteLength)
        }
        
        buffer[1..<(byteLength + 1)] = x.to(size: byteLength)
        
        return buffer
    }
    
    static func decodeFrom(_ curve: ECurve, _ buffer: Data) -> ECPoint {
        let type = buffer.bytes[0]
        let compressed = (type != 4)
        
        let byteLength = (curve.p.magnitude.bitWidth + 7) / 8
        let buf = Data(bytes: Array(buffer[1..<(byteLength + 1)]))
        let x = BigInt.from(buf)
        
        var Q: ECPoint!
        
        if compressed {
            assert(buffer.count == byteLength + 1, "Invalid sequence length")
            assert(type == 0x02 || type == 0x03, "Invalid sequence tag")
            
            let isOdd = (type == 0x03)
            Q = curve.pointFromX(isOdd, x)
        } else {
            assert(buffer.count == (1 + byteLength *  2), "Invalid sequence length")
            
            let y = BigInt.from(buffer[0..<(1+byteLength)])
            Q = fromAffine(curve: curve, x: x, y: y)
        }
        
        Q.compressed = compressed
        
        return Q
    }
    
    public func toString() -> String {
        if curve.isInfinity(self) {
            return "(INFINITY"
        }
        
        return "(" + self.affineX.toString() + "," + self.affineY.toString() + ")"
    }
}
