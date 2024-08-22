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
    public static var euPidDocType: String = "eu.europa.ec.eudiw.pid.1"
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
    //TODO: offizieller doctype ist "eu.europa.ec.eudi.pid.1". Zu finden EuPidModel.euPidDocType. Muss geändert werden wenn unser Backend das richtig umstellt
    public static let proxyTag: String = "proxy"
    public var openID4VciIssuerUrl: String?
    public var openID4VciClientId: String?
    public var openID4VciRedirectUri: String = "eudi-openid4ci://authorize"
    public var useSecureEnclave: Bool { didSet { if !SecureEnclave.isAvailable { useSecureEnclave = false } } }
    public var userAuthenticationRequired: Bool
    
    public init(storageManager: StorageManager, userAuthenticationRequired: Bool = true, openID4VciIssuerUrl: String? = nil, openID4VciClientId: String? = nil, openID4VciRedirectUri: String? = nil) {
        self.storage = storageManager
        self.openID4VciIssuerUrl = openID4VciIssuerUrl
        self.openID4VciClientId = openID4VciClientId
        self.userAuthenticationRequired = userAuthenticationRequired
        useSecureEnclave = SecureEnclave.isAvailable
        if let openID4VciRedirectUri { self.openID4VciRedirectUri = openID4VciRedirectUri }
    }
    
    public func fetchDocuments() -> [MdocDecodable] {
        var mdocs = storage.mdocModels
        if let proxy = proxyDocument(), let mdocProxy = storage.toModel(doc: proxy) {
            mdocs.insert(mdocProxy, at: 0)
        }
      return mdocs
    }

    public func fetchDocuments() async throws -> [WalletStorage.Document]? {
        var localDocs = try await loadDocuments()
        if let proxy = proxyDocument() {
            localDocs.insert(proxy, at: 0)
        }
        await storage.refreshDocModels(localDocs)
        return localDocs
    }
    
    public func fetchExternalDocuments(issueJWK: JWK? = nil, format: DataFormat, claims: [String]? = nil) async throws -> [WalletStorage.Document]? {
//        mandatory fields not needed for b''
//
//        var uniqueClaimes:[String] = []
//        if let claims {
//            let combinedClaims = claims + DocumentManager.mandatoryPIDFields
//            uniqueClaimes = Array(Set(combinedClaims))
//        }
        
        let doc: WalletStorage.Document = try await issueDocument(docType: DocumentManager.euPidDocType, format: format, external: true, issueJWK: issueJWK, claims: claims)
        return [doc]
    }
    
    func proxyDocument() -> WalletStorage.Document? {
        
        let issuerSigned = "ompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xk9gYWF2kaGRpZ2VzdElEAGZyYW5kb21QHkOzrRx2jWfxy6y/aIAg4XFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZW9QZXJzb25hbGF1c3dlaXPYGFhYpGhkaWdlc3RJRAFmcmFuZG9tUMFp9WkrWExu1d5UKU82Ig1xZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlaURldXRzY2hlctgYWFukaGRpZ2VzdElEAmZyYW5kb21QCLfK5y8xNyBlCUKU4S5DO3FlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoxOTcwLTAxLTAx2BhYW6RoZGlnZXN0SUQDZnJhbmRvbVDo6crndwsCj8V5Nx73f5z6cWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRobGVsZW1lbnRWYWx1ZWZHYWJsZXLYGFhQpGhkaWdlc3RJRARmcmFuZG9tUObN9aRtqKEfCr8oaziLOG9xZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHlsZWxlbWVudFZhbHVlYUTYGFhPpGhkaWdlc3RJRAVmcmFuZG9tUGI8+h9PW1MNsEav68Fo871xZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMThsZWxlbWVudFZhbHVl9dgYWFSkaGRpZ2VzdElEBmZyYW5kb21Q6JqvltK93KkBDo5CTOOepHFlbGVtZW50SWRlbnRpZmllcm5hZ2VfYmlydGhfeWVhcmxlbGVtZW50VmFsdWUZB7LYGFhQpGhkaWdlc3RJRAdmcmFuZG9tULFwbddmvlNDgS5tPXTWhtBxZWxlbWVudElkZW50aWZpZXJsYWdlX2luX3llYXJzbGVsZW1lbnRWYWx1ZRLYGFhUpGhkaWdlc3RJRAhmcmFuZG9tUF0jkJRZb4r+HnjQIiZm7nxxZWxlbWVudElkZW50aWZpZXJrYmlydGhfcGxhY2VsZWxlbWVudFZhbHVlZVN0YWR02BhYaaRoZGlnZXN0SUQJZnJhbmRvbVDyVmAiQfDsfhF7HvICcR9OcWVsZW1lbnRJZGVudGlmaWVycHJlc2lkZW50X2FkZHJlc3NsZWxlbWVudFZhbHVldVdlZyAxOGEKMTIzNDUgU3RhZHQKRNgYWFWkaGRpZ2VzdElECmZyYW5kb21QpDE71gZ0t9QbI8JhwSmi93FlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ5bGVsZW1lbnRWYWx1ZWFE2BhYVqRoZGlnZXN0SUQLZnJhbmRvbVAhiYto5fj9WTS0usM2FQVkcWVsZW1lbnRJZGVudGlmaWVybXJlc2lkZW50X2NpdHlsZWxlbWVudFZhbHVlZVN0YWR02BhYXaRoZGlnZXN0SUQMZnJhbmRvbVDEkEfZI4ki6QEX5WdDDddjcWVsZW1lbnRJZGVudGlmaWVydHJlc2lkZW50X3Bvc3RhbF9jb2RlbGVsZW1lbnRWYWx1ZWUxMjM0NdgYWFqkaGRpZ2VzdElEDWZyYW5kb21QwBChZEqyuF2YYOHTg7ofi3FlbGVtZW50SWRlbnRpZmllcm9yZXNpZGVudF9zdHJlZXRsZWxlbWVudFZhbHVlZ1dlZyAxOGHYGFhipGhkaWdlc3RJRA5mcmFuZG9tUJ/YhGCynoocKtvC5E/lfa5xZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVl2QPscCs5OTk5OTk5OTktMTItMzHYGFhWpGhkaWdlc3RJRA9mcmFuZG9tUMNqy/q5pTVf+lOCbM5XNFZxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHlsZWxlbWVudFZhbHVlYUTYGFhUpGhkaWdlc3RJRBBmcmFuZG9tUMQEQ/0SB7Zb7Jpg71+RrJdxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWFE2BhYX6RoZGlnZXN0SUQRZnJhbmRvbVBR9KR5eUi3Q50Mx5imNs5WcWVsZW1lbnRJZGVudGlmaWVydHNvdXJjZV9kb2N1bWVudF90eXBlbGVsZW1lbnRWYWx1ZWdpZF9jYXJk2BhYXqRoZGlnZXN0SUQSZnJhbmRvbVDnXd4dM3Ao5znnL88jpjx0cWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGVsZWxlbWVudFZhbHVl2QPsajIwMjQtMDgtMDZqaXNzdWVyQXV0aIRDoQEmoRghgFkD9tgYWQPxpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOheBhldS5ldXJvcGEuZWMuZXVkaXcucGlkLjGzAFggm6e26jfPtbkp9F2GCOX6rktDPyTWo7Nbmc+Tk/ng6+ABWCAHF9dMowErppeCwcnnfl3LEYMXlqrOL6rwgQD5b1p1tAJYIJ/6Nc1bF3SE+fWKElB+qfQ1KSNgMyWmzDalgp8QEnE7A1ggqZ5ZXtCRSo9qPks4KGFDz2mpZ6CW3X88wG2h9BngTMgEWCCW2hvI70p0op28+JLVHj8RG1xzjBlmplGO1xoarRBRzAVYILfmTTJc8dYUWcMgzT20jNo5jipwJtffwZNWgd1R096qBlggFn61QCoQEQstDsgKCcWGJf0Go4QZZtdmKv9YST4l9REHWCCQ9unLMMSCMONNasrG6uEaqTBSUuDRrKhra/KTmJn6UQhYIDzVFMXwwQw08OK4v/qxOVHrN7EmdYfUDTHwID78NBc3CVgg5GDGKgOH5hXvYaUIS6WOwGA8P1GcxvgB/0BCPtukYHMKWCBzVB8klmDO4VYjPUJ9KcNk+PUbQLg0LlGEPIIpffJzBwtYIBjVhWSO4hAwReMXcFOoQA3BumShzlauoJnSvjSu9iynDFggqjSME/SOxm42QRnKr+8ArZiaTL6HGztqeQjFgni5aQwNWCBqKmgt18v/KdtUvKgpcPKnwkuB2gLJvNoTvcTrsLQizQ5YIOnjsaF678k5DnHllQDkvk1z1LiYnLvmScqqlmz1K4TTD1ggX0xi17ydWP6JwOtqCMvRSJtXkIwgKoFLUxO5ydI9R3AQWCA0Af4AWaKVRdilqp1PjDUMtWM/qfQsNL+TlNW1PVYGDBFYIGfLNvLSuR3FQcH4LveFg3eEQQ08zErllduBaCuQpZH3ElggDWe8bq4YGWz9PiAQIDKJZIM7jFRDiTtq2Tya2vNP7a1tZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBCP601x/sgbKtKHjS2yArEERw6cTz2lONjxTakFQfoDiJYIGFAT1OPXI0fwhe/SqjLAlU6OnkLi/IohY4YmHesiTATZ2RvY1R5cGV4GGV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMWx2YWxpZGl0eUluZm+jZnNpZ25lZMB4GzIwMjQtMDgtMDZUMTQ6MDI6MzkuOTc0MTgwWml2YWxpZEZyb23AeBsyMDI0LTA4LTA2VDE0OjAyOjM5Ljk3NDE4MFpqdmFsaWRVbnRpbMB4GzIwMzQtMDgtMDRUMTQ6MDI6MzkuOTc0MTgwWlhAytbtcUUgedbrrDsHKbCWDinShd3eXhfdMWE7k6DaqhFlU30vA431WBeBeXUsIa6hucItd2JRf0YepVsbIogPYQ=="
        let privateKey = "pQECIAEhWCBoHIiBQnDRMLUT4yOLqJ1l8mrfNIgrjNnFq4RyZgxSmiJYIGD/Sabu6GejaR4eTiym1JkyjnBNcJ+f59pN+lCEyhVyI1ggC6EPCKyGci++LGWUX3fXpPFW6pYO8pyyKLMKs1qF0jo="
        
        guard let data = Data(base64URLEncoded: issuerSigned) else {
            return nil
        }
        guard let keyData = CoseKeyPrivate(base64: privateKey) else {
            return nil
        }
        let proxy = WalletStorage.Document.init(id: DocumentManager.proxyTag ,docType: DocumentManager.euPidDocType, docDataType: .cbor, data: data, privateKeyType: .x963EncodedP256, privateKey: keyData.getx963Representation(), createdAt: Date())
        return proxy
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
          return try await finalizeIssuingExternal(id: DocumentManager.proxyTag, data: data, docType: docType, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService)
        }
        return try await finalizeIssuing(id: id, data: data, docType: docType, format: format, issueReq: issueReq, openId4VCIService: openId4VCIService)
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
        let disabled = !userAuthenticationRequired || docType == nil || docType == DocumentManager.euPidDocType
        let issueReq = try await Self.authorizedAction(action: {
            return try await beginIssueDocument(id: id, privateKeyType: useSecureEnclave ? .secureEnclaveP256 : .x963EncodedP256, saveToStorage: false)
        }, disabled: disabled, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(docType ?? "", comment: "")))
        guard let issueReq else { throw LAError(.userCancel)}
        let openId4VCIService = OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, clientId: openID4VciClientId, callbackScheme: openID4VciRedirectUri)
        return (issueReq, openId4VCIService, id)
    }
    
    func finalizeIssuing(id: String, data: Data, docType: String?, format: DataFormat, issueReq: IssueRequest, openId4VCIService: OpenId4VCIService) async throws -> WalletStorage.Document  {
        let iss = IssuerSigned(data: [UInt8](data))
        let deviceResponse = iss != nil ? nil : DeviceResponse(data: [UInt8](data))
        guard let ddt = DocDataType(rawValue: format.rawValue) else { throw WalletError(description: "Invalid format \(format.rawValue)") }
        let docTypeToSave = docType ?? (format == .cbor ? iss?.issuerAuth.mso.docType ?? deviceResponse?.documents?.first?.docType : nil)
        var dataToSave: Data? = data
        if let deviceResponse {
            if let iss = deviceResponse.documents?.first?.issuerSigned { dataToSave = Data(iss.encode(options: CBOROptions())) } else { dataToSave = nil }
        }
        guard let docTypeToSave else { throw WalletError(description: "Unknown document type") }
        guard let dataToSave else { throw WalletError(description: "Issued data cannot be recognized") }
        var issued: WalletStorage.Document
        if !openId4VCIService.usedSecureEnclave {
            issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .x963EncodedP256, privateKey: issueReq.keyData, createdAt: Date())
        } else {
            issued = WalletStorage.Document(id: id, docType: docTypeToSave, docDataType: ddt, data: dataToSave, privateKeyType: .secureEnclaveP256, privateKey: issueReq.keyData, createdAt: Date())
        }
        try issueReq.saveToStorage(storage.storageService)
        try endIssueDocument(issued)
        await storage.appendDocModel(issued)
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
            ddt = .sjwt
        }
        
        let docTypeToSave = docType ?? (format == .cbor ? iss?.issuerAuth.mso.docType ?? deviceResponse?.documents?.first?.docType : nil)
        var dataToSave: Data? = data
        if let deviceResponse {
            if let iss = deviceResponse.documents?.first?.issuerSigned { dataToSave = Data(iss.encode(options: CBOROptions())) } else { dataToSave = nil }
        }
        guard let docTypeToSave else { throw WalletError(description: "Unknown document type") }
        guard let dataToSave else { throw WalletError(description: "Issued data cannot be recognized") }
        var issued: WalletStorage.Document
        if !openId4VCIService.usedSecureEnclave {
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
