/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modified by AUTHADA GmbH
Copyright (c) 2024 AUTHADA GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import WalletStorage
import LocalAuthentication
import CryptoKit
import OpenID4VCI
import SwiftCBOR

/// User wallet implementation
public final class EudiWallet: ObservableObject {
	/// Storage manager instance
	public private(set) var storage: StorageManager
	var storageService: any WalletStorage.DataStorageService { storage.storageService }
	/// Instance of the wallet initialized with default parameters
	public static private(set) var standard: EudiWallet = EudiWallet()
	/// Whether user authentication via biometrics or passcode is required before sending user data
	public var userAuthenticationRequired: Bool
	/// Trusted root certificates to validate the reader authentication certificate included in the proximity request
	public var trustedReaderCertificates: [Data]?
	/// Method to perform mdoc authentication (MAC or signature). Defaults to device MAC
	public var deviceAuthMethod: DeviceAuthMethod = .deviceMac
	/// OpenID4VP verifier api URL (used for preregistered clients)
    public var verifierApiUri: String?
	/// OpenID4VP verifier legal name (used for preregistered clients)
	public var verifierLegalName: String?
	/// OpenID4VCI issuer url
	public var openID4VciIssuerUrl: String?{
        didSet {
            docManager.openID4VciIssuerUrl = openID4VciIssuerUrl
        }
    }
	/// OpenID4VCI client id
	public var openID4VciClientId: String?{
        didSet {
            docManager.openID4VciClientId = openID4VciClientId
        }
    }
	/// OpenID4VCI redirect URI. Defaults to "eudi-openid4ci://authorize/"
	public var openID4VciRedirectUri: String = "eudi-openid4ci://authorize"
    /// Wallet attestation url
    public var walletAttestationHostUrl: String?
    /// Wallet attestation client id
    public var walletAttestationClientId: String?
	/// Use iPhone Secure Enclave to protect keys and perform cryptographic operations. Defaults to true (if available)
	public var useSecureEnclave: Bool { didSet { if !SecureEnclave.isAvailable { useSecureEnclave = false } } }
    
    public lazy var walletAttestationManager = WalletAttestationManager()

    public var docManager: DocumentManager
    
    public var externalURLService :ExternalURLService?
    
    public var issuerCertChainData: [Data]? {
        didSet {
            docManager.issuerCertChainData = issuerCertChainData
        }
    }
	
	/// Initialize a wallet instance. All parameters are optional.
    public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, verifierApiUri: String? = nil, openID4VciIssuerUrl: String? = nil, openID4VciClientId: String? = nil, openID4VciRedirectUri: String? = nil, issuerCertChainData: [Data]? = nil ) {
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		let storageService = switch storageType { case .keyChain:keyChainObj }
		storage = StorageManager(storageService: storageService)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
		#if DEBUG
		self.userAuthenticationRequired = false
		#endif
		self.verifierApiUri	= verifierApiUri
		self.openID4VciIssuerUrl = openID4VciIssuerUrl
		self.openID4VciClientId = openID4VciClientId
        self.issuerCertChainData = issuerCertChainData
		if let openID4VciRedirectUri { self.openID4VciRedirectUri = openID4VciRedirectUri }
		useSecureEnclave = SecureEnclave.isAvailable
        docManager = DocumentManager(storageManager: storage, userAuthenticationRequired: userAuthenticationRequired, openID4VciIssuerUrl: openID4VciIssuerUrl, openID4VciClientId: openID4VciClientId, openID4VciRedirectUri: openID4VciRedirectUri, issuerCertChainData: issuerCertChainData)
	}
	
	/// Prepare issuing
	/// - Parameters:
	///   - docType: document type
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: (Issue request key pair, vci service, unique id)
	func prepareIssuing(docType: String?, promptMessage: String? = nil) async throws -> (IssueRequest, OpenId4VCIService, String) {
		guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
		guard let openID4VciClientId else { throw WalletError(description: "clientId not defined")}
		let id: String = UUID().uuidString
		let issueReq = try await Self.authorizedAction(action: {
			return try await beginIssueDocument(id: id, privateKeyType: useSecureEnclave ? .secureEnclaveP256 : .x963EncodedP256, saveToStorage: false)
		}, disabled: !userAuthenticationRequired || docType == nil, dismiss: {}, localizedReason: promptMessage ?? NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(docType ?? "", comment: "")))
		guard let issueReq else { throw LAError(.userCancel)}
        let openId4VCIService = await OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, clientId: openID4VciClientId, callbackScheme: openID4VciRedirectUri, issuerCertificateChain: issuerCertChainData as [NSData]?)
		return (issueReq, openId4VCIService, id)
	}
	
	/// Issue a document with the given docType using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	///  - Parameters:
	///   - docType: Document type
	///   - format: Optional format type. Defaults to cbor
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: The document issued. It is saved in storage.
	@discardableResult public func issueDocument(docType: String, format: DataFormat = .cbor, promptMessage: String? = nil) async throws -> WalletStorage.Document {
        return try await docManager.issueDocument(docType: docType, format: format, promptMessage: promptMessage)
	}
	
	/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached
	/// - Parameters:
	///   - uriOffer: url with offer
	///   - format: data format
	///   - useSecureEnclave: whether to use secure enclave (if supported)
	/// - Returns: Offered document info model
    public func resolveOfferUrlDocTypes(uriOffer: String, format: [DataFormat] = [.cbor, .sdjwt], useSecureEnclave: Bool = true) async throws -> OfferedIssuanceModel {
		let (_, openId4VCIService, _) = try await prepareIssuing(docType: nil)
		return try await openId4VCIService.resolveOfferDocTypes(uriOffer: uriOffer, format: format)
	}
	
	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: doc types to be issued
	///   - format: data format
	///   - promptMessage: prompt message for biometric authentication (optional)
	///   - useSecureEnclave: whether to use secure enclave (if supported)
	///   - claimSet: claim set (optional)
	/// - Returns: Array of issued and stored documents
    public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], promptMessage: String? = nil, useSecureEnclave: Bool = true, claimSet: ClaimSet? = nil, txCodeValue: String?) async throws -> [WalletStorage.Document] {
		let (issueReq, openId4VCIService, id) = try await prepareIssuing(docType: docTypes.map(\.docType).joined(separator: ", "), promptMessage: promptMessage)
        let docsData = try await openId4VCIService.issueDocumentsByOfferUrl(offerUri: offerUri, docTypes: docTypes,txCodeValue: txCodeValue, useSecureEnclave: useSecureEnclave, claimSet: claimSet)
		var documents = [WalletStorage.Document]()
        var uniqueID = id
		for (i, docData) in docsData.enumerated() {
            if i > 0 {
                uniqueID = UUID().uuidString
            }
            documents.append(try await docManager.finalizeIssuing(id: uniqueID, data: docData.data!, docType: docData.docType, format: docData.format, issueReq: issueReq))
		}
		return documents
	}
	/// Begin issuing a document by generating an issue request
	///
	/// - Parameters:
	///   - id: Document identifier
	///   - issuer: Issuer function
	public func beginIssueDocument(id: String, privateKeyType: PrivateKeyType = .secureEnclaveP256, saveToStorage: Bool = true) async throws -> IssueRequest {
        return try await docManager.beginIssueDocument(id: id, privateKeyType: privateKeyType, saveToStorage: saveToStorage)
	}
	
	/// Load documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]? {
        return try await docManager.fetchDocuments()
	}

	/// Delete all documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	public func deleteDocuments() async throws  {
        return try await docManager.deleteDocuments()
	}
	
	/// Load sample data from json files
	///
	/// The mdoc data are stored in wallet storage as documents
	/// - Parameter sampleDataFiles: Names of sample files provided in the app bundle
	public func loadSampleData(sampleDataFiles: [String]? = nil) async throws {
		try? storageService.deleteDocuments()
		let docSamples = (sampleDataFiles ?? ["EUDI_sample_data"]).compactMap { Data(name:$0) }
			.compactMap(SignUpResponse.decomposeCBORSignupResponse(data:)).flatMap {$0}
			.map { Document(docType: $0.docType, docDataType: .cbor, data: $0.issData, privateKeyType: .x963EncodedP256, privateKey: $0.pkData, createdAt: Date.distantPast, modifiedAt: nil) }
		do {
		for docSample in docSamples {
			try storageService.saveDocument(docSample, allowOverwrite: true)
		}
		try await storage.loadDocuments()
		} catch {
			await storage.setError(error)
            
			throw WalletError(description: error.localizedDescription, code: (error as NSError).code)
		}
	}

	/// Prepare Service Data Parameters
	/// - Parameters:
	///   - docType: docType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A data dictionary that can be used to initialize a presentation service
    public func prepareServiceDataParameters(docType: String? = nil, dataFormat: DataFormat = .cbor ) async throws -> [String : Any] {
		var parameters: [String: Any]
		switch dataFormat {
		case .cbor:
            guard var docs = try await docManager.fetchDocuments(), docs.count > 0 else { throw WalletError(description: "No documents found") }
			if let docType { docs = docs.filter { $0.docType == docType} }
			if let docType { guard docs.count > 0 else { throw WalletError(description: "No documents of type \(docType) found") } }
			let cborsWithKeys = docs.compactMap { $0.getCborData() }
			guard cborsWithKeys.count > 0 else { throw WalletError(description: "Documents decode error") }
			parameters = [InitializeKeys.document_signup_issuer_signed_obj.rawValue: Dictionary(uniqueKeysWithValues: cborsWithKeys.map(\.iss)), InitializeKeys.device_private_key_obj.rawValue: Dictionary(uniqueKeysWithValues: cborsWithKeys.map(\.dpk))]
			if let trustedReaderCertificates { parameters[InitializeKeys.trusted_certificates.rawValue] = trustedReaderCertificates }
			parameters[InitializeKeys.device_auth_method.rawValue] = deviceAuthMethod.rawValue
		default:
			fatalError("jwt format not implemented")
		}
		return parameters
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - docType: DocType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
    public func beginPresentation(flow: FlowType, docType: String? = nil, dataFormat: DataFormat = .cbor) async -> PresentationSession {
		do {
            let parameters = try await prepareServiceDataParameters(docType: docType, dataFormat: dataFormat)
			let docIdAndTypes = storage.getDocIdsToTypes()
			switch flow {
			case .ble:
				let bleSvc = try BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc, docIdAndTypes: docIdAndTypes, userAuthenticationRequired: userAuthenticationRequired)
			case .openid4vp(let qrCode):
                let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode, openId4VpVerifierApiUri: self.verifierApiUri, openId4VpVerifierLegalName: self.verifierLegalName, docManager: self.docManager)
				return PresentationSession(presentationService: openIdSvc, docIdAndTypes: docIdAndTypes, userAuthenticationRequired: userAuthenticationRequired)
			default:
				return PresentationSession(presentationService: FaultPresentationService(error: PresentationSession.makeError(str: "Use beginPresentation(service:)")), docIdAndTypes: docIdAndTypes, userAuthenticationRequired: false)
			}
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error), docIdAndTypes: [], userAuthenticationRequired: false)
		}
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - service: A ``PresentationService`` instance
	///   - docType: DocType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(service: any PresentationService) -> PresentationSession {
		PresentationSession(presentationService: service, docIdAndTypes: storage.getDocIdsToTypes(), userAuthenticationRequired: userAuthenticationRequired)
	}
	
	@MainActor
	/// Perform an action after user authorization via TouchID/FaceID/Passcode
	/// - Parameters:
	///   - dismiss: Action to perform if the user cancels authorization
	///   - action: Action to perform after user authorization
	public static func authorizedAction<T>(action: () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		return try await authorizedAction(isFallBack: false, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
	}
	
	/// Wrap an action with TouchID or FaceID authentication
	/// - Parameters:
	///   - isFallBack: true if fallback (ask for pin code)
	///   - dismiss: action to dismiss current page
	///   - action: action to perform after authentication
	static func authorizedAction<T>(isFallBack: Bool = false, action: () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		guard !disabled else {
			return try await action()
		}
		let context = LAContext()
		var error: NSError?
		let policy: LAPolicy = .deviceOwnerAuthentication
		if context.canEvaluatePolicy(policy, error: &error) {
			do {
				let success = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
				if success {
					return try await action()
				}
				else { dismiss()}
			} catch let laError as LAError {
				if !isFallBack, laError.code == .userFallback {
					return try await authorizedAction(isFallBack: true, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
				} else {
					dismiss()
					return nil
				}
			}
		} else if let error {
			throw WalletError(description: error.localizedDescription, code: error.code)
		}
		return nil
	}
}
