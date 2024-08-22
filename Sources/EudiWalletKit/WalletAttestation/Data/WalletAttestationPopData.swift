/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//
//  WalletAttestationPopData.swift
//

import Foundation

import Foundation

public struct WalletAttestationPopData: Codable {
    public let issuer: String?
    public let audience: String?
    public let nonce: String?
    public let issuedAt: Date?
    public let expirationTime: Date?
    public let jwtId: String?
    
    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case audience = "aud"
        case nonce = "nonce"
        case issuedAt = "iat"
        case expirationTime = "exp"
        case jwtId = "jti"
    }
    
    public init(
        issuer: String?,
        audience: String?,
        nonce: String?,
        issuedAt: Date?,
        expirationTime: Date?,
        jwtId: String? = UUID().uuidString
    ) {
        self.issuer = issuer
        self.audience = audience
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.expirationTime = expirationTime
        self.jwtId = jwtId
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.issuer, forKey: .issuer)
        try container.encodeIfPresent(self.audience, forKey: .audience)
        try container.encodeIfPresent(self.nonce, forKey: .nonce)
        if let issueDate = self.issuedAt {
            let issueAtInt = Int64(issueDate.timeIntervalSince1970)
            try container.encodeIfPresent(issueAtInt, forKey: .issuedAt)
        }
        if let expTime = self.expirationTime {
            let expTimeInt = Int64(expTime.timeIntervalSince1970)
            try container.encodeIfPresent(expTimeInt, forKey: .expirationTime)
        }
        try container.encodeIfPresent(self.jwtId, forKey: .jwtId)
    }
}
