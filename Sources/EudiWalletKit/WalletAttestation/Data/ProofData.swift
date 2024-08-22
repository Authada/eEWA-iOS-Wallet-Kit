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
//  ProofData.swift
//  

import Foundation

public struct Proof: Codable {
    public let proofData: ProofData?
    
    enum CodingKeys: String, CodingKey {
        case proofData = "proof"
    }
    
    public init(
        proofData: ProofData
    ) {
        self.proofData = proofData
    }
}

public struct ProofData: Codable {
  public let proofType: String?
  public let jwt: String?
  
  enum CodingKeys: String, CodingKey {
    case proofType = "proof_type"
    case jwt = "jwt"
  }
  
  public init(
    jwt: String
  ) {
    self.proofType = "jwt"
    self.jwt = jwt
  }
}
