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
//  MdocDocument.swift
//

import Foundation
import MdocDataModel18013

public struct MdocDocument : WalletDocument {
    
    public var id: String {
        return mdoc.id
    }
    public var createdAt: Date {
        return mdoc.createdAt
    }
    public var docTypes: [String] {
        return [mdoc.docType]
    }
    public var docType: String {
        get {
            return mdoc.docType
        }
        set {
            mdoc.docType = newValue
        }
    }
    public var docFormat: DataFormat? {
        return .cbor
    }
    public var displayStrings: [NameValue] {
        return mdoc.displayStrings
    }
    public var displayImages: [NameImage] {
        return mdoc.displayImages
    }
    
    //MARK: -
    
    private var mdoc :MdocDecodable
    
    init(mdoc: MdocDecodable) {
        self.mdoc = mdoc
    }
    
    //MARK: - Functions
    
    public func getBearersName() -> (first: String, last: String)? {
      var name: (first: String, last: String)?

      switch mdoc {
      case let pid as EuPidModel:
        if let firstName = pid.given_name, let lastName = pid.family_name {
          name = (firstName, lastName)
        }
      case let mdl as IsoMdlModel:
        if let firstName = mdl.givenName, let lastName = mdl.familyName {
          name = (firstName, lastName)
        }
      case let generic as GenericMdocModel:
        if
          let firstName = generic.displayStrings.first(
            where: {
              $0.name.replacingOccurrences(of: "_", with: "").lowercased() == "givenname"
            }
          )?.value,
          let lastName = generic.displayStrings.first(
            where: {
              $0.name.replacingOccurrences(of: "_", with: "").lowercased() == "familyname"
            }
          )?.value {
          name = (firstName, lastName)
        }
      default: break
      }

      return name
    }
    
    public func getPortraitImageData() -> Data? {
        var imageData: Data?
        
        switch mdoc {
        case let mdl as IsoMdlModel:
            if let portrait = mdl.portrait {
                imageData = Data(portrait)
            }
        default: break
        }
        
        return imageData
    }
    
    public func expiryDateValue() -> String? {
        let dateString :String?
        switch mdoc {
        case let pid as EuPidModel:
            dateString = pid.expiry_date
        case let mdl as IsoMdlModel:
            dateString = mdl.expiryDate
        case let generic as GenericMdocModel:
            dateString = generic.displayStrings.first(
                where: {
                    $0.name.replacingOccurrences(of: "_", with: "").lowercased() == "expirydate"
                }
            )?.value
        default:
            dateString = nil
        }
        return dateString
    }
    
}
