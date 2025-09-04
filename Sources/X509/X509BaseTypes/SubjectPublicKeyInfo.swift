//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1
struct SubjectPublicKeyInfo: DERImplicitlyTaggable, Hashable, Sendable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    var algorithmIdentifier: AlgorithmIdentifier
    var key: ASN1BitString
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        // The SPKI block looks like this:
        //
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //   algorithm         AlgorithmIdentifier,
        //   subjectPublicKey  BIT STRING
        // }
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try AlgorithmIdentifier(derEncoded: &nodes)
            let key = try ASN1BitString(derEncoded: &nodes)

            return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }
    init(algorithmIdentifier: AlgorithmIdentifier, key: ASN1BitString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
    internal init(algorithmIdentifier: AlgorithmIdentifier, key: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = ASN1BitString(bytes: key[...])
    }
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.key)
        }
    }
}
