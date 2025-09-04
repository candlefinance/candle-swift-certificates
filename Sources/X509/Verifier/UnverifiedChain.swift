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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct UnverifiedCertificateChain: Sendable, Hashable {
    var certificates: [Certificate]

    init(_ certificates: [Certificate]) {
        precondition(!certificates.isEmpty)
        self.certificates = certificates
    }
    public var leaf: Certificate {
        self.certificates.first!
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension UnverifiedCertificateChain: RandomAccessCollection {
    public var startIndex: Int {
        self.certificates.startIndex
    }
    public var endIndex: Int {
        self.certificates.endIndex
    }
    public subscript(position: Int) -> Certificate {
        get {
            self.certificates[position]
        }
    }
}
