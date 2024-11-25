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
//  DocumentManager.swift
//  

import Foundation
import WalletStorage
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SwiftCBOR
import JOSESwift
import CryptoKit
import LocalAuthentication
import OpenID4VCI

public class DocumentManager: NSObject {
    public private(set) var storage: StorageManager
    public static var euPidDocTypeMdoc: String = "eu.europa.ec.eudi.pid.1"
    public static var euPidDocTypeSdjwt: String = "urn:eu.europa.ec.eudi:pid:1"
//  mandatory fields not needed for b''
//    public static var mandatoryPIDFields = [
//        "family_name",
//        "given_name",
//        "issuance_date",
//        "expiry_date",
//        "birth_date",
//        "issuing_country",
//        "issuing_authority",
//      ]
    public var openID4VciIssuerUrl: String?
    public var openID4VciClientId: String?
    public var openID4VciRedirectUri: String = "eudi-openid4ci://authorize"
    public var useSecureEnclave: Bool { didSet { if !SecureEnclave.isAvailable { useSecureEnclave = false } } }
    public var userAuthenticationRequired: Bool
    public var issuerCertChainData: [Data]?
    private let proxyPID = ProxyPidDocument()
    
    public init(storageManager: StorageManager, userAuthenticationRequired: Bool = true, openID4VciIssuerUrl: String? = nil, openID4VciClientId: String? = nil, openID4VciRedirectUri: String? = nil, issuerCertChainData: [Data]? = nil ) {
        self.storage = storageManager
        self.openID4VciIssuerUrl = openID4VciIssuerUrl
        self.openID4VciClientId = openID4VciClientId
        self.userAuthenticationRequired = userAuthenticationRequired
        self.issuerCertChainData = issuerCertChainData
        useSecureEnclave = SecureEnclave.isAvailable
        if let openID4VciRedirectUri { self.openID4VciRedirectUri = openID4VciRedirectUri }
    }

    public func fetchDocuments() async throws -> [WalletStorage.Document]? {
        var localDocs = try await loadDocuments()
        if let proxyDoc = proxyPID.storageDocument {
            localDocs.insert(proxyDoc, at: 0)
        }
        await storage.refreshWalletDocuments(localDocs)
        return localDocs
    }
    
    public func fetchDocuments(for idsToFetch:[String]) async throws -> [WalletStorage.Document]? {
        var filteredDocs :[WalletStorage.Document] = []
        if let localDocs = try await self.fetchDocuments() {
            filteredDocs = localDocs.filter {
                return idsToFetch.contains($0.id)
            }
        }
        return filteredDocs
    }
    
    public func fetchExternalDocuments(issueJWK: JWK? = nil, format: DataFormat, docType: String, claims: [String]? = nil) async throws -> [WalletStorage.Document]? {
//        mandatory fields not needed for b''
//
//        var uniqueClaimes:[String] = []
//        if let claims {
//            let combinedClaims = claims + DocumentManager.mandatoryPIDFields
//            uniqueClaimes = Array(Set(combinedClaims))
//        }
        
        let doc: WalletStorage.Document = try await issueDocument(docType: docType, format: format, external: true, issueJWK: issueJWK, claims: claims)
        return [doc]
    }
    
    func loadDocuments() async throws -> [WalletStorage.Document]  {
        guard let localDocuments = try await storage.loadDocuments() else {
            return []
        }
        return localDocuments
    }
    
    func deleteDocuments() async throws {
        return try await storage.deleteDocuments()
    }
    
    @discardableResult public func issueDocument(docType: String,
                                                 format: DataFormat,
                                                 promptMessage: String? = nil,
                                                 external:Bool = false,
                                                 issueJWK: JWK? = nil,
                                                 claims: [String]? = nil) async throws -> WalletStorage.Document {
        let (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: docType, promptMessage: promptMessage)
        let data = try await openId4VCIService.issueDocument(docType: docType, format: format, useSecureEnclave: useSecureEnclave, verifierJWK: issueJWK,claims: claims)
        if external {
          return try await finalizeIssuingExternal(id: ProxyPidDocument.proxyTagID, data: data, docType: docType, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService)
        }
        return try await finalizeIssuing(id: id, data: data, docType: docType, format: format, issueReq: issueReq)
    }
    
    func beginIssueDocument(id: String, privateKeyType: PrivateKeyType = .secureEnclaveP256, saveToStorage: Bool = true) async throws -> IssueRequest {
        let request = try IssueRequest(id: id, privateKeyType: privateKeyType)
        if saveToStorage { try request.saveToStorage(storage.storageService) }
        return request
    }
    
    func prepareIssuing(docType: String?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
        guard let openID4VciIssuerUrl else { 
            throw WalletError(description: "issuer Url not defined")}
        guard let openID4VciClientId else {
            throw WalletError(description: "clientId not defined")}
        let id: String = UUID().uuidString
        let disabled = !userAuthenticationRequired || docType == nil || ProxyPidDocument.proxyPidSupportedDocTypes.contains(docType ?? "")
        let issueReq = try await Self.authorizedAction(action: {
            return try await beginIssueDocument(id: id, privateKeyType: useSecureEnclave ? .secureEnclaveP256 : .x963EncodedP256, saveToStorage: false)
        }, disabled: disabled, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(docType ?? "", comment: "")))
        guard let issueReq else { throw LAError(.userCancel)}
        let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, clientId: openID4VciClientId, callbackScheme: openID4VciRedirectUri, issuerCertificateChain: issuerCertChainData as [NSData]?)
        return (issueReq, openId4VCIService, id)
    }
    
    func finalizeIssuing(id: String, data: Data, docType: String?, format: DataFormat, issueReq: IssueRequest) async throws -> WalletStorage.Document  {
        
        let ddt :DocDataType
        switch format {
        case .cbor:
            ddt = .cbor
        case .sdjwt:
            ddt = .sdjwt
        }
        
        var dataToSave: Data? = data
        var docTypeToSave = docType
        
        if ddt == .cbor {
            let iss = IssuerSigned(data: [UInt8](data))
            let deviceResponse = iss != nil ? nil : DeviceResponse(data: [UInt8](data))
            docTypeToSave = docType ?? (format == .cbor ? iss?.issuerAuth.mso.docType ?? deviceResponse?.documents?.first?.docType : nil)
            if let deviceResponse {
                if let iss = deviceResponse.documents?.first?.issuerSigned { dataToSave = Data(iss.encode(options: CBOROptions())) } else { dataToSave = nil }
            }
        }
        
        guard let docTypeToSave else { throw WalletError(description: "Unknown document type") }
        guard let dataToSave else { throw WalletError(description: "Issued data cannot be recognized") }
        let issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: issueReq.privateKeyType, privateKey: issueReq.keyData, createdAt: Date())
        try endIssueDocument(issued)
        await storage.appendDoc(issued)
        await storage.refreshPublishedVars()
        return issued
    }
    
    func finalizeIssuingExternal(id: String, data: Data, docType: String?, format: DataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService) async throws -> WalletStorage.Document  {
        let iss = IssuerSigned(data: [UInt8](data))
        let deviceResponse = iss != nil ? nil : DeviceResponse(data: [UInt8](data))
        
        let ddt :DocDataType
        
        switch format {
        case .cbor:
            ddt = .cbor
        case .sdjwt:
            ddt = .sdjwt
        }
        
        let docTypeToSave = docType ?? (format == .cbor ? iss?.issuerAuth.mso.docType ?? deviceResponse?.documents?.first?.docType : nil)
        var dataToSave: Data? = data
        if let deviceResponse {
            if let iss = deviceResponse.documents?.first?.issuerSigned { dataToSave = Data(iss.encode(options: CBOROptions())) } else { dataToSave = nil }
        }
        guard let docTypeToSave else { throw WalletError(description: "Unknown document type") }
        guard let dataToSave else { throw WalletError(description: "Issued data cannot be recognized") }
        var issued: WalletStorage.Document
        if await !openId4VCIService.usedSecureEnclave {
            issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .x963EncodedP256, privateKey: issueReq.keyData, createdAt: Date())
        } else {
            issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .secureEnclaveP256, privateKey: issueReq.keyData, createdAt: Date())
        }
        return issued
    }
    
    public func endIssueDocument(_ issued: WalletStorage.Document) throws {
        try storage.storageService.saveDocumentData(issued, dataToSaveType: .doc, dataType: issued.docDataType.rawValue, allowOverwrite: true)
        try storage.storageService.saveDocumentData(issued, dataToSaveType: .key, dataType: issued.privateKeyType!.rawValue, allowOverwrite: true)
    }
    
    public static func authorizedAction<T>(action: () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
        return try await EudiWallet.authorizedAction(isFallBack: false, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
    }
}
