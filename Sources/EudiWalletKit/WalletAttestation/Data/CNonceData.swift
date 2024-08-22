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
//  CNonceData.swift
//

import Foundation

public struct CNonceData: Codable {
  public let cNonce: String?
  public let cNonceExpiresInSeconds: Int?
  
  enum CodingKeys: String, CodingKey {
    case cNonce = "c_nonce"
    case cNonceExpiresInSeconds = "c_nonce_expires_in"
  }
  
  public init(
    cNonce: String?,
    cNonceExpiresInSeconds: Int?
  ) {
    self.cNonce = cNonce
    self.cNonceExpiresInSeconds = cNonceExpiresInSeconds
  }
}
