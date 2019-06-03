# swift-ecc
## ECC encryption signature library implemented in Swift

### Generate Random Keypair
    if let privateKey = PrivateKey.randomKey() {
        print("Private Key: \(privateKey.toString() ?? "Failed to generate.")")

        if let publicKey = privateKey.toPublic() {
            print("Public Key: \(publicKey.toString())")
        }
    }
    
### Generate Private Key from WIF
    if let privateKey = PrivateKey.fromWif("YOUR WIF HERE") {
        print("Private Key: \(privateKey.toString() ?? "Failed to generate.")")

        if let publicKey = privateKey.toPublic() {
            print("Public Key: \(publicKey.toString())")
        }
    }
