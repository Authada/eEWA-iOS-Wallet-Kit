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
//  WalletAttestationRequestData.swift
//

import Foundation

public struct WalletAttestationRequestData: Codable {
    public let issuer: String?
    public let audience: String?
    public let appAttestation: AppAttestationData?
    public let nonce: String?
    public let issuedAt: Date?
    
    enum CodingKeys: String, CodingKey {
        case issuer = "iss"
        case audience = "aud"
        case appAttestation = "app_attestation"
        case nonce = "nonce"
        case issuedAt = "iat"
    }
    
    public init(
        issuer: String?,
        audience: String?,
        appAttestation: AppAttestationData?,
        nonce: String?,
        issuedAt: Date?
    ) {
        self.issuer = issuer
        self.audience = audience
        self.appAttestation = appAttestation
        self.nonce = nonce
        self.issuedAt = issuedAt
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.issuer, forKey: .issuer)
        try container.encodeIfPresent(self.audience, forKey: .audience)
        try container.encodeIfPresent(self.appAttestation, forKey: .appAttestation)
        try container.encodeIfPresent(self.nonce, forKey: .nonce)
        if let issueDate = self.issuedAt {
            let issueAtInt = Int64(issueDate.timeIntervalSince1970)
            try container.encodeIfPresent(issueAtInt, forKey: .issuedAt)
        }
    }
}
