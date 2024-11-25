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

Created on 04/10/2023

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
import SwiftCBOR
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SiopOpenID4VP
import JOSESwift
import SwiftyJSON
import Logging
import X509
import eudi_lib_sdjwt_swift
import JSONWebAlgorithms
import JSONWebSignature
import CryptoKit
import WalletStorage
/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP – Draft 18 specification
public class OpenId4VpService: PresentationService {
	public var status: TransferStatus = .initialized
	var openid4VPlink: String
	// map of document id to data
	var docs: [String: IssuerSigned]!
	var iaca: [SecCertificate]!
	var dauthMethod: DeviceAuthMethod
	var devicePrivateKeys: [String: CoseKeyPrivate]!
	var logger = Logger(label: "OpenId4VpService")
	var presentationDefinition: PresentationDefinition?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var openId4VpVerifierApiUri: String?
	var openId4VpVerifierLegalName: String?
	var readerAuthValidated: Bool = false
	var readerCertificateIssuer: String?
	var readerCertificateValidationMessage: String?
	var mdocGeneratedNonce: String!
	var sessionTranscript: SessionTranscript!
	var eReaderPub: CoseKey?
    var docManager: DocumentManager?
	public var flow: FlowType
    
    var authenticatedChannelKeyForPIDIssuing: JWK? //use authenticated channel for PID issuing if this key is != nil

    public init(parameters: [String: Any], qrCode: Data, openId4VpVerifierApiUri: String?, openId4VpVerifierLegalName: String?, docManager: DocumentManager? = nil) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		guard let (docs, devicePrivateKeys, iaca, dauthMethod) = MdocHelpers.initializeData(parameters: parameters) else {
			throw PresentationSession.makeError(str: "MDOC_DATA_NOT_AVAILABLE")
		}
		self.docs = docs; self.devicePrivateKeys = devicePrivateKeys; self.iaca = iaca; self.dauthMethod = dauthMethod
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
		self.openId4VpVerifierApiUri = openId4VpVerifierApiUri
		self.openId4VpVerifierLegalName = openId4VpVerifierLegalName
        self.docManager = docManager
	}
	
	public func startQrEngagement() async throws -> String? { nil }
	
    //MARK: - Request
    
	///  Receive request from an openid4vp URL
	///
	/// - Returns: The requested items.
	public func receiveRequest() async throws -> [String: Any] {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw PresentationSession.makeError(str: "Invalid link \(openid4VPlink)") }
		siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri, verifierLegalName: openId4VpVerifierLegalName))
			switch try await siopOpenId4Vp.authorize(url: openid4VPURI)  {
			case .notSecured(data: _):
				throw PresentationSession.makeError(str: "Not secure request received.")
			case let .jwt(request: resolvedRequestData):
				self.resolvedRequestData = resolvedRequestData
				switch resolvedRequestData {
				case let .vpToken(vp):
                    authenticatedChannelKeyForPIDIssuing = authenticatedChannelKeyForPIDIssuningFromVpToken(vpTokenData: vp)
					if let key = vp.clientMetaData?.jwkSet?.keys.first(where: { $0.use == "enc"}), let x = key.x, let xd = Data(base64URLEncoded: x), let y = key.y, let yd = Data(base64URLEncoded: y), let crv = key.crv, let crvType = MdocDataModel18013.ECCurveType(crvName: crv)  {
						logger.info("Found jwks public key with curve \(crv)")
						eReaderPub = CoseKey(x: [UInt8](xd), y: [UInt8](yd), crv: crvType)
					}
					let responseUri = if case .directPostJWT(let uri) = vp.responseMode { uri.absoluteString } else { "" }
					mdocGeneratedNonce = Openid4VpUtils.generateMdocGeneratedNonce()
					sessionTranscript = Openid4VpUtils.generateSessionTranscript(clientId: vp.client.id,
						responseUri: responseUri, nonce: vp.nonce, mdocGeneratedNonce: mdocGeneratedNonce)
					logger.info("Session Transcript: \(sessionTranscript.encode().toHexString()), for clientId: \(vp.client.id), responseUri: \(responseUri), nonce: \(vp.nonce), mdocGeneratedNonce: \(mdocGeneratedNonce!)")
					self.presentationDefinition = vp.presentationDefinition
					let items = try Openid4VpUtils.parsePresentationDefinition(vp.presentationDefinition, logger: logger)
					guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
					var result: [String: Any] = [UserRequestKeys.valid_items_requested.rawValue: items]
					if let ln = resolvedRequestData.legalName { result[UserRequestKeys.reader_legal_name.rawValue] = ln }
					if let readerCertificateIssuer {
						result[UserRequestKeys.reader_auth_validated.rawValue] = readerAuthValidated
						result[UserRequestKeys.reader_certificate_issuer.rawValue] = MdocHelpers.getCN(from: readerCertificateIssuer)
						result[UserRequestKeys.reader_certificate_validation_message.rawValue] = readerCertificateValidationMessage
					}
					return result
				default: throw PresentationSession.makeError(str: "SiopAuthentication request received, not supported yet.")
				}
			}
	}
    
    private func authenticatedChannelPossibleForPIDIssuningFromVpToken(vpTokenData vp:ResolvedRequestData.VpTokenData) -> Bool {
        let allowedAuthChannelAlgorithms = ["DVS-P256-SHA256-HS256", "DVS-P384-SHA256-HS256", "DVS-P512-SHA256-HS256"]
        
        let inputDescriptors = vp.presentationDefinition.inputDescriptors
        for desc in inputDescriptors {
            let matchingProxyPidDocTypes = ProxyPidDocument.firstProxyPidDocTypeMatching(inputDescritor: desc)
            if matchingProxyPidDocTypes != nil {
                guard let formats = desc.formatContainer?.formats else {
                    continue
                }
                for format in formats {
                    guard let formatType = format["designation"].string else {
                        continue
                    }
                    
                    var algorithms: [JSON]?
                    if (formatType == "mso_mdoc") {
                        algorithms = format["alg"].array
                    }
                    else if (formatType == "vc+sd-jwt") {
                        algorithms = format["sd-jwt_alg_values"].array
                    }
                    
                    guard let algorithms else {
                        continue
                    }
                    
                    for alg in algorithms {
                        if let algName = alg.string, allowedAuthChannelAlgorithms.contains(algName) {
                            return true
                        }
                    }
                }
            }
        }
        return false
    }
    
    private func authenticatedChannelKeyForPIDIssuningFromVpToken(vpTokenData vp:ResolvedRequestData.VpTokenData) -> JWK? {
        
        let allowedAuthChannelAlgorithmFound = authenticatedChannelPossibleForPIDIssuningFromVpToken(vpTokenData: vp)
        
        if allowedAuthChannelAlgorithmFound {
            if let keys = vp.clientMetaData?.jwkSet?.keys {
                for key in keys {
                    if key.kty == "EC" {
                        do {
                            let keyJSONData = try JSONEncoder().encode(key)
                            let jwk = try ECPublicKey(data:keyJSONData)
                            return jwk
                        }
                        catch {
                            print("error converting key to JSON")
                        }
                    }
                }
            }
        }
        
        return nil
    }
    
    //MARK: - Repsponse
	
	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws {
		
        guard let pd = presentationDefinition, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpTokenConsent(nil, pd, resolved, onSuccess)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend)")
        
        
        
        let inputDescriptorFormats = pd.inputDescriptors
        
        var usePIDIssuing = false
        let pidInputDescriptorFormats = inputDescriptorFormats.filter({
            if ProxyPidDocument.firstProxyPidDocTypeMatching(inputDescritor: $0) != nil && itemsToSend[ProxyPidDocument.proxyTagID]?[$0.id] != nil {
                return true
            }
            return false
        })
        if pidInputDescriptorFormats.count > 0 {
            usePIDIssuing = true
        }
        
        let supportedInputDescriptorFormats = inputDescriptorFormats.filter { $0.formatContainer?.formats.contains(where: { $0["designation"].string?.lowercased() == "vc+sd-jwt" || $0["designation"].string?.lowercased() == "mso_mdoc" }) ?? false}
        
        if supportedInputDescriptorFormats.count <= 0 {
            throw PresentationSession.makeError(str: "all request formats unsupported")
        }
        
        guard let docMgr = self.docManager else {
            throw PresentationSession.makeError(str: "document manager missing")
        }
        
        let idsToPresent = itemsToSend.compactMap { (key: String, value: [String : [String]]) in
            if key != ProxyPidDocument.proxyTagID {
                return key
            }
            return nil
        }
        var docsToPresent :[WalletStorage.Document] = try await docMgr.fetchDocuments(for: idsToPresent) ?? []
                
        if usePIDIssuing {
            guard let choosenPIDInputDescriptorFormat = pidInputDescriptorFormats.first else {
                throw PresentationSession.makeError(str: "all PID request formats unsupported")
            }
            guard let choosenFormat = choosenPIDInputDescriptorFormat.formatContainer?.formats.filter({ $0["designation"].string?.lowercased() == "vc+sd-jwt" || $0["designation"].string?.lowercased() == "mso_mdoc" }).first else {
                throw PresentationSession.makeError(str: "no supported PID format found")
            }
            
            var requestedFormat :DataFormat = .cbor
            var requestedPidDocType :String = DocumentManager.euPidDocTypeMdoc
            if (choosenFormat["designation"].string?.lowercased() == "vc+sd-jwt") {
                requestedFormat = .sdjwt
                requestedPidDocType = ProxyPidDocument.firstProxyPidDocTypeMatching(inputDescritor: choosenPIDInputDescriptorFormat) ?? DocumentManager.euPidDocTypeSdjwt
            }
            
            let claims = itemsToSend[ProxyPidDocument.proxyTagID]?[choosenPIDInputDescriptorFormat.id]
            
            guard let issuerSignedDocs = try await docMgr.fetchExternalDocuments(issueJWK: authenticatedChannelKeyForPIDIssuing, format: requestedFormat, docType: requestedPidDocType, claims: claims) else {
                throw PresentationSession.makeError(str: "DOCUMENT_ERROR")
            }
            guard let issuedDoc = issuerSignedDocs.first else {
                throw PresentationSession.makeError(str: "DOCUMENT_ERROR")
            }
            docsToPresent.insert(issuedDoc, at: 0)
        }
                        
        var descriptorMaps :Array<DescriptorMap> = []
        var verifiablePresentations :[VpToken.VerifiablePresentation] = []
        var vpTokenApu: Base64URL? = nil
        
        let count = docsToPresent.count
        
        for (i, docToPresent) in docsToPresent.enumerated() {
            
            let path = count > 1 ? "$[\(i)]" : "$"
            
            if docToPresent.docDataType == .sdjwt {
                                
                //Check if format for docType is requested
                let matchingInputDescriptors = inputDescriptorFormats.filter {
                    if $0.formatContainer?.formats.contains(where: { $0["designation"].string?.lowercased() == "vc+sd-jwt" }) ?? false {
                        let docTypesOfInputDescritor : [String] = Openid4VpUtils.vctFilterDocTypes(inDesc: $0) ?? []
                        if (docTypesOfInputDescritor.contains(docToPresent.docType)) {
                            return true
                        }
                    }
                    return false
                }
                
                //Search matching input descriptor
                var choosenInputDescriptor = matchingInputDescriptors.first
                let namespaceDictKeys = itemsToSend[docToPresent.id]?.keys
                if let namespaceDictKeys {
                    for inDesc in matchingInputDescriptors {
                        if namespaceDictKeys.contains(inDesc.id) {
                            choosenInputDescriptor = inDesc
                            break
                        }
                    }
                }
                                            
                guard let finalChoosenInputDescriptor = choosenInputDescriptor else {
                    throw PresentationSession.makeError(str: "document does not match requested data type (vc+sd-jwt) for document type \(docToPresent.docType)")
                }
                
                guard let choosenFormat = finalChoosenInputDescriptor.formatContainer?.formats.filter({ $0["designation"].string?.lowercased() == "vc+sd-jwt"}).first else {
                    throw PresentationSession.makeError(str: "no supported format found for \(docToPresent.docType)")
                }
                
                let claimNames = itemsToSend[docToPresent.id]?[finalChoosenInputDescriptor.id]
                
                let serializedSDJWT = try createSDJWTPresentation(docToPresent, resolved, claimNames: claimNames, choosenFormat)
                
                let decriptorMap :DescriptorMap = DescriptorMap(id: finalChoosenInputDescriptor.id, format: "vc+sd-jwt", path: path)
                let vp :VpToken.VerifiablePresentation = .generic(serializedSDJWT)
                
                descriptorMaps.append(decriptorMap)
                verifiablePresentations.append(vp)
            }
            else {
                guard let (iss, dpk) = docToPresent.getCborData() else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR")}
                let docsToSend = [docToPresent.id:iss.1]
                let devicePrivateKey = [docToPresent.id:dpk.1]
                
#if DEBUG
                if usePIDIssuing {
                    let algorithm = iss.1.issuerAuth.verifyAlgorithm
                    switch algorithm  {
                    case .dvsp256, .dvsp384, .dvsp512:
                        print("authenticated channel: \(algorithm)")
                    default:
                        print("authenticated channel: none")
                    }
                }
#endif
                
                guard let (deviceResponse, _, _) = try MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, issuerSigned: docsToSend, selectedItems: itemsToSend, eReaderKey: eReaderPub, devicePrivateKeys: devicePrivateKey, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature) else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
                // Obtain consent
                let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
                
                
                //Check if format for docType is requested
                let matchingInputDescriptor = pd.inputDescriptors.filter {
                    if $0.formatContainer?.formats.contains(where: { $0["designation"].string?.lowercased() == "mso_mdoc" }) ?? false && $0.id == docToPresent.docType {
                        return true
                    }
                    return false
                }
                if (matchingInputDescriptor.count <= 0) {
                    throw PresentationSession.makeError(str: "document does not match requested data type (mso_mdoc) for document type \(docToPresent.docType)")
                }
                
                let decriptorMap :DescriptorMap = DescriptorMap(id: docToPresent.docType, format: "mso_mdoc", path: path)
                let vp :VpToken.VerifiablePresentation = .msoMdoc(vpTokenStr)
                
                descriptorMaps.append(decriptorMap)
                verifiablePresentations.append(vp)
                
                if vpTokenApu == nil {
                    vpTokenApu = mdocGeneratedNonce.base64urlEncode
                }
            }
        }
        
        let consent :ClientConsent = .vpToken(vpToken: VpToken(apu:vpTokenApu, verifiablePresentations: verifiablePresentations), presentationSubmission: .init(id: UUID().uuidString, definitionID: pd.id, descriptorMap: Array(descriptorMaps)))
        
		try await SendVpTokenConsent(consent, pd, resolved, onSuccess)
	}
    
    
    fileprivate func createSDJWTPresentation(_ issuedDoc: WalletStorage.Document, _ resolved: ResolvedRequestData, claimNames: [String]?, _ choosenFormat:JSON) throws -> String {
        
        let sdJWTString = String(data: issuedDoc.data, encoding: .utf8) ?? ""
        let sdjwt = try CompactParser(serialisedString: sdJWTString).getSignedSdJwt()
        
        let nonce, audience :String
        let client :Client
        
        switch resolved {
        case .idToken(request: let request):
            nonce = request.nonce
            client = request.client
        case .vpToken(request: let request):
            nonce = request.nonce
            client = request.client
        case .idAndVpToken(request: _):
            throw PresentationSession.makeError(str: "id and vp token unsupported")
        }
        
        switch client {
        case .preRegistered(clientId: let clientId, legalName: _):
            audience = clientId
        case .redirectUri(clientId: let clientId):
            audience = clientId.absoluteString
        case .x509SanDns(clientId: let clientId, certificate: _):
            audience = clientId
        case .x509SanUri(clientId: let clientId, certificate: _):
            audience = clientId
        case .didClient(did: let did):
            audience = did.uri.absoluteString
        case .attested(clientId: let clientId):
            audience = clientId
        }
        
        
        
        guard let privateKeyData = issuedDoc.privateKey else {
            throw PresentationSession.makeError(str: "no private key")
        }
        
        let privateKey:SecKey?
        let kbJWTSigningAlgorithm:String?
        
        do {
            switch issuedDoc.privateKeyType {
            case .derEncodedP256:
                let key = try P256.KeyAgreement.PrivateKey(derRepresentation: privateKeyData)
                privateKey = try key.toSecKey()
                kbJWTSigningAlgorithm = "ES256"
            case .pemStringDataP256:
                let key = try P256.KeyAgreement.PrivateKey(pemRepresentation: String(data: privateKeyData, encoding: .utf8) ?? "")
                privateKey = try key.toSecKey()
                kbJWTSigningAlgorithm = "ES256"
            case .x963EncodedP256:
                let key = try P256.KeyAgreement.PrivateKey(x963Representation: privateKeyData)
                privateKey = try key.toSecKey()
                kbJWTSigningAlgorithm = "ES256"
            case .secureEnclaveP256:
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: privateKeyData)
                privateKey = try key.toSecKey()
                kbJWTSigningAlgorithm = "ES256"
            case .none:
                throw PresentationSession.makeError(str: "no key type")
            }
        }
        catch {
            throw PresentationSession.makeError(str: "no SecKey")
        }
        
        guard let privateKey, let kbJWTSigningAlgorithm else {
            throw PresentationSession.makeError(str: "no private key found")
        }
        
        //Check if RP supports KBJWT signing algorithm
        if let allowedKbJWTAlgs = choosenFormat.dictionaryObject?["kb-jwt_alg_values"] as? [String] {
            if !allowedKbJWTAlgs.contains(kbJWTSigningAlgorithm) {
                throw PresentationSession.makeError(str: "unsupported KBJWT signing algorithm \(kbJWTSigningAlgorithm)")
            }
        }
        
        guard let kbJWTAlg = JSONWebAlgorithms.SigningAlgorithm(rawValue: kbJWTSigningAlgorithm) else {
            throw PresentationSession.makeError(str: "unknown KBJWT signing algorithm: \(kbJWTSigningAlgorithm)")
        }
                
        let kbJwtPayload = JSON(["nonce":nonce, "aud":audience, "iat":Int64(Date().timeIntervalSince1970)])
        
        let kbjwt = try KBJWT(header: DefaultJWSHeaderImpl(algorithm: kbJWTAlg), kbJwtPayload: kbJwtPayload)
        
        let finalDisclosures :[Disclosure]
        if let claimNames {
            //Filter disclosures
            finalDisclosures = sdjwt.filteredDisclosures(with: claimNames) ?? []
        }
        else {
            finalDisclosures = sdjwt.disclosures
        }
        
        let holderSDJWTRepresentation = try SDJWTIssuer
            .presentation(holdersPrivateKey: privateKey,
                          signedSDJWT: sdjwt,
                          disclosuresToPresent: finalDisclosures,
                          keyBindingJWT:kbjwt)
        
        let serializedSDJWT = CompactSerialiser(signedSDJWT: holderSDJWTRepresentation).serialised
        return serializedSDJWT
    }
    
	fileprivate func SendVpTokenConsent(_ consent: ClientConsent?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?) async throws {
        let consent = consent ?? .negative(message: "Rejected")
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri, verifierLegalName: openId4VpVerifierLegalName))
		let result: DispatchOutcome = try await siopOpenId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
			onSuccess?(url)
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
	}
	
	lazy var chainVerifier: CertificateTrust = { [weak self] certificates in
		let chainVerifier = X509CertificateChainVerifier()
		let verified = try? chainVerifier.verifyCertificateChain(base64Certificates: certificates)
		var result = chainVerifier.isChainTrustResultSuccesful(verified ?? .failure)
		guard let self, let b64cert = certificates.first, let data = Data(base64Encoded: b64cert), let cert = SecCertificateCreateWithData(nil, data as CFData), let x509 = try? X509.Certificate(derEncoded: [UInt8](data)) else { return result }
		self.readerCertificateIssuer = x509.subject.description
		let (isValid, validationMessages, _) = SecurityHelpers.isMdocCertificateValid(secCert: cert, usage: .mdocReaderAuth, rootCerts: self.iaca ?? [])
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = validationMessages.joined(separator: "\n")
		return result
	}
	
	/// OpenId4VP wallet configuration
	func getWalletConf(verifierApiUrl: String?, verifierLegalName: String?) -> WalletOpenId4VPConfiguration? {
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
					let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
        #warning("TODO: .x509SanUri(trust: chainVerifier), .x509SanDns(trust: chainVerifier) removed from supportedClientIDSchemes")
		var supportedClientIdSchemes: [SupportedClientIdScheme] = [.x509SanDns(trust: chainVerifier)]
		if let verifierApiUrl, let verifierLegalName {
			let verifierMetaData = PreregisteredClient(clientId: "Verifier", legalName: verifierLegalName, jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUrl)/wallet/public-keys.json")!))
			supportedClientIdSchemes += [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])]
	  }
		let res = WalletOpenId4VPConfiguration(subjectSyntaxTypesSupported: [.decentralizedIdentifier, .jwkThumbprint], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: supportedClientIdSchemes, vpFormatsSupported: [])
		return res
	}
	
}

