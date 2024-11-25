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
//  SdjwtDocument.swift
//

import Foundation
import eudi_lib_sdjwt_swift
import MdocDataModel18013
import SwiftyJSON

public struct SdjwtDocument : WalletDocument {
    public private(set) var id: String
    public private(set) var createdAt: Date
    public private(set) var docType: String
    public var docTypes: [String] {
        return [docType]
    }
    public var docFormat: DataFormat? {
        return .sdjwt
    }
    public private(set) var displayStrings: [NameValue]
    public var displayImages: [NameImage] {
        return [] //TODO: SDJWT Lösung hierfür finden
    }
    
    private let displayDateFormatter :DateFormatter = {
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        dateFormatter.timeStyle = .none
        if let languagePrefix = Locale.preferredLanguages.first {
            dateFormatter.locale = Locale(identifier: languagePrefix)
        }
        return dateFormatter
    }()
    
    //MARK: - Keys
    
    enum CodingKeys: String, CodingKey {
        case issuedAt = "iat"
        case expirationTime = "exp"
    }
    
    //MARK: -
    
    private var sdjwt :SignedSDJWT
    private var expiryDate :Date?
    private var expiryDateString :String? //Dateformat yyyy-MM-dd
    private var dateOfIssue :Date?
    
    init(id: String, signedSDJWT: SignedSDJWT, createdAt:Date, docType:String) {
        self.sdjwt = signedSDJWT
        self.id = id
        self.createdAt = createdAt
        self.docType = docType
        self.displayStrings = []
        extractDisplayValues()
        extractStandardDates()
    }
    
    //MARK: - Functions
    
    public func getBearersName() -> (first: String, last: String)? {
        //TODO: Implement if needed
        return nil
    }
    
    public func getPortraitImageData() -> Data? {
        //TODO: Implement if needed
        return nil
    }
    
    public func expiryDateValue() -> String? {
        //Dateformat yyyy-MM-dd
        return expiryDateString
    }
    
    //MARK: - Build Data
    
    
    private mutating func extractStandardDates() {
        expiryDate = nil
        expiryDateString = nil
        dateOfIssue = nil
        
        if let expValue = displayStrings.first(where: {$0.name == CodingKeys.expirationTime.rawValue})?.value {
            expiryDate = displayDateFormatter.date(from: expValue)
            if let date = expiryDate {
                let dateFomatter = DateFormatter()
                dateFomatter.dateFormat = "yyyy-MM-dd"
                expiryDateString = dateFomatter.string(from: date)
            }
        }
        if let iatValue = displayStrings.first(where: {$0.name == CodingKeys.issuedAt.rawValue})?.value {
            dateOfIssue = displayDateFormatter.date(from: iatValue)
        }
    }
    
    private func dateStringFrom(timeIntervalSince1970:String) -> String? {
        if let time = TimeInterval(timeIntervalSince1970) {
            let date = Date(timeIntervalSince1970: time)
            return displayDateFormatter.string(from: date)
        }
        return nil
    }
    
    private func convert(value:JSON, forKey key:String) -> NameValue? {
        var stringValue :String? = nil
        var childs :[NameValue]? = nil
        var mdocDataType :MdocDataType? = nil
        var order = 0
        
        switch (value.type) {
        case .string:
            stringValue = value.string
            mdocDataType = .string
        case .number:
            stringValue = value.stringValue
        case .bool:
            stringValue = value.stringValue
            mdocDataType = .boolean
        case .array:
            stringValue = "<Array>" //TODO: support in future
            mdocDataType = .array
        case .dictionary:
            stringValue = "<Dictionary>"
            if let valueDict = value.dictionary {
                childs = valueDict.compactMap({ (key: String, value: JSON) in
                    return convert(value:value, forKey:key)
                })
            }
            mdocDataType = .dictionary
        case .null:
            stringValue = ""
        case .unknown:
            stringValue = "<unknown>"
        }
        
        if var stringValue {
            switch key {
            case CodingKeys.issuedAt.rawValue:
                //Date of issue
                order = 1
                if let formattedDate = self.dateStringFrom(timeIntervalSince1970: stringValue) {
                    stringValue = formattedDate
                }
            case CodingKeys.expirationTime.rawValue:
                //Date of expiry
                order = 2
                if let formattedDate = self.dateStringFrom(timeIntervalSince1970: stringValue) {
                    stringValue = formattedDate
                }
            case "iss":
                order = 3
            case _ where key.hasPrefix("vct"):
                order = 4
            case "cnf":
                order = 5
            default:
                order = 0
            }
            return NameValue(name: key, value: stringValue, mdocDataType: mdocDataType, order: order, children: childs)
        }
        return nil
    }
    
    private mutating func extractDisplayValues() {
        do {
            let claims = try sdjwt.recreateClaims().recreatedClaims
            if let dict = claims.dictionary {
                let result = dict.compactMap { (key: String, value: JSON) in
                    return convert(value:value, forKey:key)
                }
                self.displayStrings = result
            }
        }
        catch {
            self.displayStrings = []
            print("error reading document data for \(self.docType)")
        }
    }
}

