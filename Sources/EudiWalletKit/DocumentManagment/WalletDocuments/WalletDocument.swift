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
//  WalletDocument.swift
//  

import Foundation
import MdocDataModel18013

public protocol WalletDocument {
    var id: String { get }
    var createdAt: Date { get }
    var docTypes: [String] { get }
    var docFormat: DataFormat? { get }
    
    var displayStrings: [NameValue] { get }
    var displayImages: [NameImage] { get }
    
    //MARK: - Functions
    
    func getBearersName() -> (first: String, last: String)?
    func getPortraitImageData() -> Data?
    func expiryDateValue() -> String?
}
