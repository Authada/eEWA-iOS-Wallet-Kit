/*
 * Copyright (c) 2023 European Commission
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
 *
 * Modified by AUTHADA GmbH
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

import Foundation
@preconcurrency import OpenID4VCI
import JOSESwift
import MdocDataModel18013
import AuthenticationServices
import Logging
import CryptoKit
import Security
import WalletStorage

public class OpenId4VCIService: NSObject, ASWebAuthenticationPresentationContextProviding {
    let issueReq: IssueRequest
    let credentialIssuerURL: String
    var privateKey: SecKey!
    var publicKey: SecKey!
    var bindingKey: BindingKey!
    var usedSecureEnclave: Bool!
    let logger: Logger
    let config: OpenId4VCIConfig
    let alg = JWSAlgorithm(.ES256)
    let issuerCertificateChain: [NSData]?
    static var metadataCache = [String: CredentialOffer]()
    
    init(issueRequest: IssueRequest, credentialIssuerURL: String, clientId: String, callbackScheme: String, issuerCertificateChain: [NSData]? = nil) {
        self.issueReq = issueRequest
        self.credentialIssuerURL = credentialIssuerURL
        self.issuerCertificateChain = issuerCertificateChain
        logger = Logger(label: "OpenId4VCI")
        config = .init(clientId: clientId, authFlowRedirectionURI: URL(string: callbackScheme)!)
    }
    
    fileprivate func initSecurityKeys(_ useSecureEnclave: Bool) throws {
        usedSecureEnclave = useSecureEnclave && SecureEnclave.isAvailable
        if !usedSecureEnclave {
            let key = try P256.KeyAgreement.PrivateKey(x963Representation: issueReq.keyData)
            privateKey = try key.toSecKey()
        } else {
            let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: issueReq.keyData)
            privateKey = try seKey.toSecKey()
        }
        publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
        let publicKeyJWK = try ECPublicKey(publicKey: publicKey,additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
        bindingKey = .jwk(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKey)
    }
    
    /// Issue a document with the given `docType` using OpenId4Vci protocol
    /// - Parameters:
    ///   - docType: the docType of the document to be issued
    ///   - format: format of the exchanged data
    ///   - useSecureEnclave: use secure enclave to protect the private key
    ///   - verifierJWK: needed to support authenticated channel between verifier and issuer
    /// - Returns: The data of the document
    public func issueDocument(docType: String, format: DataFormat, useSecureEnclave: Bool = true, verifierJWK: JWK?, claims:[String]? = nil) async throws -> Data {
        try initSecurityKeys(useSecureEnclave)
        
        var verifierPub :VerifierPub? = nil
        if let jwk = verifierJWK {
            verifierPub = VerifierPub(jwk: jwk)
        }
        
        var claimSet:ClaimSet?
        if let claimIn = claims {
            switch format {
            case .cbor:
                var claims:[(Namespace, ClaimName)] = []
                for claimName in claimIn {
                    claims.append((docType,claimName))
                }
                claimSet = ClaimSet.msoMdoc(MsoMdocFormat.MsoMdocClaimSet(
                    claims: claims
                ))
            case .sdjwt:
                var claims:[ClaimName: Claim] = [:]
                for claimName in claimIn {
                    claims[claimName] = Claim()
                }
                claimSet = ClaimSet.sdJwtVc(SdJwtVcFormat.SdJwtVcClaimSet(claims: claims))
            }
        }
        
        
        let str = try await issueByDocType(docType, format: format, claimSet: claimSet, verifierPub: verifierPub)
        switch format {
        case .cbor:
            guard let data = Data(base64URLEncoded: str) else { throw OpenId4VCIError.dataNotValid }
            return data
        case .sdjwt:
            guard let data = str.data(using: .utf8) else { throw OpenId4VCIError.dataNotValid }
            return data
        }
    }
    
    /// Resolve issue offer and return available document metadata
    /// - Parameters:
    ///   - uriOffer: Uri of the offer (from a QR or a deep link)
    ///   - format: format of the exchanged data
    /// - Returns: The data of the document
    public func resolveOfferDocTypes(uriOffer: String, format: [DataFormat] = [.cbor, .sdjwt]) async throws -> OfferedIssuanceModel {
        let offerURL :URL
        if #available(iOS 17.0, *) {
            guard let uriOfferNormalized = uriOffer.removingPercentEncoding else { throw WalletError(description: "Invalid uri offer \(uriOffer)")}
            guard let offerUrlNormalized = URL(string: uriOfferNormalized) else { throw WalletError(description: "Invalid URL string \(uriOffer)")}
            offerURL = offerUrlNormalized
        }
        else {
            guard let offerUrlNormalized = URL(string: uriOffer) else { throw WalletError(description: "Invalid URL string \(uriOffer)")}
            offerURL = offerUrlNormalized
        }
        let result = await CredentialOfferRequestResolver().resolve(source: try .init(urlString: offerURL.absoluteString))
        switch result {
        case .success(let offer):
            let code: Grants.PreAuthorizedCode? = switch offer.grants {
            case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode
            case .both(_, let preAuthorizedCode): preAuthorizedCode
            case .authorizationCode(_), .none: nil
            }
            Self.metadataCache[uriOffer] = offer
            let signedMetadata = offer.credentialIssuerMetadata.signedMetadata
            let issuerValid = try? await self.authenticateOffer(signedMetaData: signedMetadata)
            let credentialInfo = format.compactMap {
                return try? getCredentialIdentifiers(issuerName: offer.credentialIssuerIdentifier.url.absoluteString, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, format: $0)
            }.flatMap{$0}
            let offeredIssuanceModel = OfferedIssuanceModel(docModels: credentialInfo.map(\.offered), txCodeSpec: code?.txCode, isValidated: issuerValid ?? false)
            return offeredIssuanceModel
        case .failure(let error):
            throw WalletError(description: "Unable to resolve credential offer: \(error.localizedDescription)")
        }
    }
    
    func getIssuer(offer: CredentialOffer) throws -> Issuer {
        var dpopConstructor:DPoPConstructor? = nil
        
        switch bindingKey {
        case .jwk(let algorithm, let jwk, let privateKey, _):
            dpopConstructor = DPoPConstructor(algorithm: algorithm, jwk: jwk, privateKey: privateKey)
            break
        default: break
        }
        
        return try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, dpopConstructor: dpopConstructor)
    }
    
    func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String? = nil, useSecureEnclave: Bool = true, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> [(data:Data?, docType:String, format:DataFormat)] {
        try initSecurityKeys(useSecureEnclave)
        guard let offer = Self.metadataCache[offerUri] else { throw WalletError(description: "offerUri not resolved. resolveOfferDocTypes must be called first")}
        
        let credentialInfo = docTypes.flatMap {
            let doctype = $0.docType
            return $0.docFormat.compactMap{
                try? getCredentialIdentifier(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, docType: doctype, format: $0)
            }
        }
        
        let code: Grants.PreAuthorizedCode? =
        switch offer.grants {
        case .preAuthorizedCode(let preAuthorizedCode):    preAuthorizedCode;
        case .both(_, let preAuthorizedCode):    preAuthorizedCode;
        case .authorizationCode(_), .none: nil
        }
        
        let txCodeSpec: TxCode? = code?.txCode
        let preAuthorizedCode: String? = code?.preAuthorizedCode
        
        let issuer = try getIssuer(offer: offer)
        if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil { throw WalletError(description: "A transaction code is required for this offer") }
        
        let authorized = if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) {
            try await authorizeRequestWithPreAuthCodeUseCase(issuer: issuer, offer: offer, authCode:authCode, txCode: txCodeValue)
        } else {
            try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
        }
        
        let data = await credentialInfo.asyncCompactMap {
            do {
                logger.info("Starting issuing with identifer \($0.identifier.value) and scope \($0.scope)")
                let str = try await issueOfferedCredentialWithProof(authorized, offer: offer, issuer: issuer, credentialConfigurationIdentifier: $0.identifier, claimSet: claimSet)
                switch $0.format {
                case .cbor:
                    return (Data(base64URLEncoded: str), $0.docType, $0.format)
                case .sdjwt:
                    return (str.data(using: .utf8), $0.docType, $0.format)
                }
            } catch {
                logger.error("Failed to issue document with scope \($0.scope)")
                logger.info("Exception: \(error)")
                return nil
            }
        }
        Self.metadataCache.removeValue(forKey: offerUri)
        return data
    }
    
    func issueByDocType(_ docType: String, format: DataFormat, claimSet: ClaimSet? = nil, verifierPub: VerifierPub?) async throws -> String {
        let credentialIssuerIdentifier = try CredentialIssuerId(credentialIssuerURL)
        let issuerMetadata = await CredentialIssuerMetadataResolver().resolve(source: .credentialIssuer(credentialIssuerIdentifier))
        switch issuerMetadata {
        case .success(let metaData):
            if let authorizationServer = metaData?.authorizationServers?.first, let metaData {
                let authServerMetadata = await AuthorizationServerMetadataResolver().resolve(url: authorizationServer)
                
                var dpopConstructor:DPoPConstructor? = nil
                
                switch bindingKey {
                case .jwk(let algorithm, let jwk, let privateKey, _):
                    dpopConstructor = DPoPConstructor(algorithm: algorithm, jwk: jwk, privateKey: privateKey)
                    break
                default: break
                }
                
                let (credentialConfigurationIdentifier, _, _, _) = try getCredentialIdentifier(credentialsSupported: metaData.credentialsSupported, docType: docType, format: format)
                let offer = try CredentialOffer(credentialIssuerIdentifier: credentialIssuerIdentifier, credentialIssuerMetadata: metaData, credentialConfigurationIdentifiers: [credentialConfigurationIdentifier], grants: nil, authorizationServerMetadata: try authServerMetadata.get())
                // Authorize with auth code flow
                let issuer = try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: config, dpopConstructor: dpopConstructor, verifierPub: verifierPub)
                let authorized = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer, claims: claimSet)
                return try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
            } else {
                throw WalletError(description: "Invalid authorization server")
            }
        case .failure:
            throw WalletError(description: "Invalid issuer metadata")
        }
    }
    
    private func authenticateOffer(signedMetaData: String?) async throws -> Bool {
        guard let signedMetaData = signedMetaData,
              let certificateChain = self.issuerCertificateChain
        else {
            return false
        }
        let authenticator = JWTAuthenticator(jwtString: signedMetaData, trustedCerts: certificateChain)
        switch try authenticator.validateIssuerTrust(subject: credentialIssuerURL) {
        case .success:
            return true
        case .failure(let string):
            return false
        case .unknown(let string):
            return false
        }
    }
    
    private func issueOfferedCredentialInternal(_ authorized: AuthorizedRequest, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet?) async throws -> String {
        switch authorized {
        case .noProofRequired:
            return try await noProofRequiredSubmissionUseCase(issuer: issuer, noProofRequiredState: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
        case .proofRequired:
            return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: authorized, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
        }
    }
    
    private func issueOfferedCredentialWithProof(_ authorized: AuthorizedRequest, offer: CredentialOffer, issuer: Issuer, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet? = nil) async throws -> String {
        let issuerMetadata = offer.credentialIssuerMetadata
        guard issuerMetadata.credentialsSupported.keys.contains(where: { $0.value == credentialConfigurationIdentifier.value }) else {
            throw WalletError(description: "Cannot find credential identifier \(credentialConfigurationIdentifier.value) in offer")
        }
        return try await issueOfferedCredentialInternal(authorized, issuer: issuer, credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
    }
    
    func getCredentialIdentifier(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], docType: String, format: DataFormat) throws -> (identifier: CredentialConfigurationIdentifier, scope: String, docType: String, format: DataFormat) {
        switch format {
        case .cbor:
            guard let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.docType == docType { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope else {
                logger.error("No credential for docType \(docType). Currently supported credentials: \(credentialsSupported.values)")
                throw WalletError(description: "Issuer does not support doc type\(docType)")
            }
            logger.info("Currently supported cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
            return (identifier: credential.key, scope: scope, docType: docType, format: format)
        case .sdjwt:
            guard let credential = credentialsSupported.first(where: { if case .sdJwtVc(let sdjwtCred) = $0.value, sdjwtCred.vct == docType { true } else { false } }), case let .sdJwtVc(sdJwtVcConf) = credential.value, let scope = sdJwtVcConf.scope else {
                logger.error("No credential for docType \(docType). Currently supported credentials: \(credentialsSupported.values)")
                throw WalletError(description: "Issuer does not support doc type\(docType)")
            }
            logger.info("Currently supported cryptographic suites: \(sdJwtVcConf.credentialSigningAlgValuesSupported)")
            return (identifier: credential.key, scope: scope, docType: docType, format: format)
        }
    }
    
    func getCredentialIdentifier(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], scope: String, format: DataFormat) throws -> (identifier: CredentialConfigurationIdentifier, scope: String) {
        switch format {
        case .cbor:
            guard let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, msoMdocCred.scope == scope { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value, let scope = msoMdocConf.scope else {
                logger.error("No credential for scope \(scope). Currently supported credentials: \(credentialsSupported.values)")
                throw WalletError(description: "Issuer does not support scope \(scope)")
            }
            logger.info("Currently supported cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
            return (identifier: credential.key, scope: scope)
        case .sdjwt:
            guard let credential = credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtCred) = $0.value, sdJwtCred.scope == scope { true } else { false } }), case let .sdJwtVc(sdJwtConf) = credential.value, let scope = sdJwtConf.scope else {
                logger.error("No credential for scope \(scope). Currently supported credentials: \(credentialsSupported.values)")
                throw WalletError(description: "Issuer does not support scope \(scope)")
            }
            logger.info("Currently supported cryptographic suites: \(sdJwtConf.credentialSigningAlgValuesSupported)")
            return (identifier: credential.key, scope: scope)
        }
    }
    
    func getCredentialIdentifiers(issuerName: String, credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], format: DataFormat) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String, offered: OfferedDocModel)] {
        switch format {
        case .cbor:
            let credentialInfos = credentialsSupported.compactMap {
                if case .msoMdoc(let msoMdocCred) = $0.value, let scope = msoMdocCred.scope, case let offered = OfferedDocModel(issuerName: issuerName, docType: msoMdocCred.docType, displayName: msoMdocCred.display.getName() ?? msoMdocCred.docType, docFormat: [.cbor]) { (identifier: $0.key, scope: scope, offered: offered) } else { nil } }
            return credentialInfos
        case .sdjwt:
            let credentialInfos = credentialsSupported.compactMap {
                if case .sdJwtVc(let sdJwtCred) = $0.value, let scope = sdJwtCred.scope, case let offered = OfferedDocModel(issuerName: issuerName, docType: sdJwtCred.vct!, displayName: sdJwtCred.display.getName() ?? sdJwtCred.vct!, docFormat: [.sdjwt]) { (identifier: $0.key, scope: scope, offered: offered) } else { nil } }
            return credentialInfos
        }
    }
    
    private func clientAssertionNonce(endpointURL:URL) async throws -> String {
        
        let urlSession = URLSession.shared
        let result = try await urlSession.data(from: endpointURL)
        
        let data = result.0
        if let response = result.1 as? HTTPURLResponse, response.statusCode == 200, response.mimeType?.lowercased() == "application/json" {
            
            let jsonData = try JSONDecoder().decode(CNonceData.self, from: data)
            if let nonce = jsonData.cNonce {
                //print("pushedAuthorizationRequestEndpoint nonce = \(nonce)")
                return nonce
            }
        }
        
        throw WalletError(description: "No challenge for client assertion received. (\(endpointURL.absoluteString)")
    }
    
    private func authorizeRequestWithPreAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer, claims:ClaimSet? = nil, authCode: IssuanceAuthorization, txCode: String?) async throws -> AuthorizedRequest {
        var walletAttestationPopNeeded = false
        var issuerURL :String? = nil
        var pushedAuthorizationRequestEndpoint = ""
        
        if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
            pushedAuthorizationRequestEndpoint = endpoint
            issuerURL = metaData.issuer
            if let authMethods = metaData.tokenEndpointAuthMethodsSupported, authMethods.contains("attest_jwt_client_auth") {
                walletAttestationPopNeeded = true
            }
        } else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
            pushedAuthorizationRequestEndpoint = endpoint
            issuerURL = metaData.issuer
            if let authMethods = metaData.tokenEndpointAuthMethodsSupported, authMethods.contains("attest_jwt_client_auth") {
                walletAttestationPopNeeded = true
            }
        }
        
        var tokenClientAssertion :ClientAssertion? = nil
        
        if (walletAttestationPopNeeded) {
            guard let pushedAuthorizationRequestEndpointURL = URL(string: pushedAuthorizationRequestEndpoint) else {
                throw WalletError(description: "Invalid pushedAuthorizationRequestEndpoint URL")
            }
            
            guard let issuerURL else {
                throw WalletError(description: "Invalid issuer URL")
            }
            
            let nonce = try await clientAssertionNonce(endpointURL:pushedAuthorizationRequestEndpointURL)
            let walletAttMgr = EudiWallet.standard.walletAttestationManager
            tokenClientAssertion = try await walletAttMgr.clientAssertion(cnonce: nonce, audience: issuerURL)
        }
        
        return try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, clientId: config.clientId, transactionCode: txCode, clientAssertion: tokenClientAssertion).get()
    }
    
    private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer, claims:ClaimSet? = nil) async throws -> AuthorizedRequest {
		var pushedAuthorizationRequestEndpoint = ""
        var walletAttestationPopNeeded = false
        var issuerURL :String? = nil
		if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
            issuerURL = metaData.issuer
            if let authMethods = metaData.tokenEndpointAuthMethodsSupported, authMethods.contains("attest_jwt_client_auth") {
                walletAttestationPopNeeded = true
            }
		} else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint {
			pushedAuthorizationRequestEndpoint = endpoint
            issuerURL = metaData.issuer
            if let authMethods = metaData.tokenEndpointAuthMethodsSupported, authMethods.contains("attest_jwt_client_auth") {
                walletAttestationPopNeeded = true
            }
		}
        
        guard !pushedAuthorizationRequestEndpoint.isEmpty else { throw WalletError(description: "pushed Authorization Request Endpoint is nil") }
        logger.info("--> [AUTHORIZATION] Placing PAR to AS server's endpoint \(pushedAuthorizationRequestEndpoint)")
        
        var assertionNonce :String? = nil
        var parClientAssertion :ClientAssertion? = nil
        
        if (walletAttestationPopNeeded) {
            guard let pushedAuthorizationRequestEndpointURL = URL(string: pushedAuthorizationRequestEndpoint) else {
                throw WalletError(description: "Invalid pushedAuthorizationRequestEndpoint URL")
            }
            
            guard let issuerURL else {
                throw WalletError(description: "Invalid issuer URL")
            }
            
            let nonce = try await clientAssertionNonce(endpointURL:pushedAuthorizationRequestEndpointURL)
            assertionNonce = nonce
            let walletAttMgr = EudiWallet.standard.walletAttestationManager
            parClientAssertion = try await walletAttMgr.clientAssertion(cnonce: nonce, audience: issuerURL)
        }
		
        let parPlaced = try await issuer.pushAuthorizationCodeRequest(credentialOffer: offer, clientAssertion:parClientAssertion, claims: claims)
		
		if case let .success(request) = parPlaced, case let .par(parRequested) = request {
			logger.info("--> [AUTHORIZATION] Placed PAR. Get authorization code URL is: \(parRequested.getAuthorizationCodeURL)")
			let authorizationCode = try await getAauthorizationCode(
                getAuthorizationCodeUrl: parRequested.getAuthorizationCodeURL.url) ?? { throw WalletError(description: "Could not retrieve authorization code") }()
			logger.info("--> [AUTHORIZATION] Authorization code retrieved")
			let unAuthorized = await issuer.handleAuthorizationCode(parRequested: request, authorizationCode: .authorizationCode(authorizationCode: authorizationCode))
			switch unAuthorized {
			case .success(let request):
                
                var tokenClientAssertion :ClientAssertion? = nil
                
                if (walletAttestationPopNeeded) {
                    if let nonce = assertionNonce, let issuerURL {
                        let walletAttMgr = EudiWallet.standard.walletAttestationManager
                        tokenClientAssertion = try await walletAttMgr.clientAssertion(cnonce: nonce, audience: issuerURL)
                    }
                    else {
                        throw WalletError(description: "Failed to create client assertion for access token request")
                    }
                }
                
				let authorizedRequest = await issuer.requestAccessToken(authorizationCode: request, clientAssertion: tokenClientAssertion)
				if case let .success(authorized) = authorizedRequest, case let .noProofRequired(token, _, _, _) = authorized {
                    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(token.accessToken)")
                    return authorized
				}
                else if case let .success(authorized) = authorizedRequest, case let .proofRequired(token, _, _, _, _) = authorized {
                    logger.info("--> [AUTHORIZATION] Authorization code exchanged with access token : \(token.accessToken)")
                    return authorized
                }
			case .failure(let error):
				throw  WalletError(description: error.localizedDescription)
			}
		} else if case let .failure(failure) = parPlaced {
			throw WalletError(description: "Authorization error: \(failure.localizedDescription)")
		}
		throw WalletError(description: "Failed to get push authorization code request")
	}
    
    private func getAauthorizationCode(getAuthorizationCodeUrl: URL) async throws -> String? {
        
        return try await startEiDAndGetAuthCode(getAuthorizationCodeUrl: getAuthorizationCodeUrl)
    }
    
	private func noProofRequiredSubmissionUseCase(issuer: Issuer, noProofRequiredState: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier, claimSet: ClaimSet? = nil) async throws -> String {
		switch noProofRequiredState {
		case .noProofRequired:
			let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: credentialConfigurationIdentifier,	claimSet: claimSet)
			let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
			let requestOutcome = try await issuer.requestSingle(noProofRequest: noProofRequiredState, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
			switch requestOutcome {
			case .success(let request):
				switch request {
				case .success(let response):
					if let result = response.credentialResponses.first {
						switch result {
						case .deferred(let transactionId):
							return try await deferredCredentialUseCase(issuer: issuer, authorized: noProofRequiredState, transactionId: transactionId)
						case .issued(let credential, _):
							return credential
						}
					} else {
						throw WalletError(description: "No credential response results available")
					}
				case .invalidProof(let cNonce, _):
					return try await proofRequiredSubmissionUseCase(issuer: issuer, authorized: noProofRequiredState.handleInvalidProof(cNonce: cNonce), credentialConfigurationIdentifier: credentialConfigurationIdentifier)
				case .failed(error: let error):
					throw WalletError(description: error.localizedDescription)
				}
			case .failure(let error):
				throw WalletError(description: error.localizedDescription)
			}
		default: throw WalletError(description: "Illegal noProofRequiredState case")
		}
	}
	
	private func proofRequiredSubmissionUseCase(issuer: Issuer, authorized: AuthorizedRequest, credentialConfigurationIdentifier: CredentialConfigurationIdentifier?, claimSet: ClaimSet? = nil) async throws -> String {
		guard let credentialConfigurationIdentifier else { throw WalletError(description: "Credential configuration identifier not found") }
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: credentialConfigurationIdentifier, claimSet: claimSet)
		let responseEncryptionSpecProvider = { Issuer.createResponseEncryptionSpec($0) }
		let requestOutcome = try await issuer.requestSingle(proofRequest: authorized, bindingKey: bindingKey, requestPayload: payload, responseEncryptionSpecProvider: responseEncryptionSpecProvider)
		switch requestOutcome {
		case .success(let request):
			switch request {
			case .success(let response):
				if let result = response.credentialResponses.first {
					switch result {
					case .deferred(let transactionId):
						return try await deferredCredentialUseCase(issuer: issuer, authorized: authorized, transactionId: transactionId)
					case .issued(let credential, _):
						return credential
					}
				} else {
					throw WalletError(description: "No credential response results available")
				}
			case .invalidProof:
				throw WalletError(description: "Although providing a proof with c_nonce the proof is still invalid")
			case .failed(let error):
				throw WalletError(description: error.localizedDescription)
			}
		case .failure(let error): throw WalletError(description: error.localizedDescription)
		}
	}
	
	private func deferredCredentialUseCase(issuer: Issuer, authorized: AuthorizedRequest, transactionId: TransactionId) async throws -> String {
		logger.info("--> [ISSUANCE] Got a deferred issuance response from server with transaction_id \(transactionId.value). Retrying issuance...")
		let deferredRequestResponse = try await issuer.requestDeferredIssuance(proofRequest: authorized, transactionId: transactionId)
		switch deferredRequestResponse {
		case .success(let response):
			switch response {
			case .issued(let credential):
				return credential
			case .issuancePending(let transactionId):
				throw WalletError(description: "Credential not ready yet. Try after \(transactionId.interval ?? 0)")
			case .errored(_, let errorDescription):
				throw WalletError(description: "\(errorDescription ?? "Something went wrong with your deferred request response")")
			}
		case .failure(let error):
			throw WalletError(description: error.localizedDescription)
		}
	}
	
	@MainActor
	private func loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL) async throws -> String? {
		return try await withCheckedThrowingContinuation { c in
			let authenticationSession = ASWebAuthenticationSession(url: getAuthorizationCodeUrl, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { optionalUrl, optionalError in
				guard optionalError == nil else { c.resume(throwing: OpenId4VCIError.authRequestFailed(optionalError!)); return }
				guard let url = optionalUrl else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl); return }
				guard let code = url.getQueryStringParameter("code") else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoCode); return }
				c.resume(returning: code)
			}
			authenticationSession.prefersEphemeralWebBrowserSession = true
			authenticationSession.presentationContextProvider = self
			authenticationSession.start()
		}
	}
    
    @MainActor
    private func startEiDAndGetAuthCode(getAuthorizationCodeUrl: URL) async throws -> String? {
        let externEIDHandler = ExternalEIDHandler(authorizationCodeURL: getAuthorizationCodeUrl)
        return try await externEIDHandler.startEiDAndGetAuthCode()
    }

	
	public func presentationAnchor(for session: ASWebAuthenticationSession)
	-> ASPresentationAnchor {
#if os(iOS)
		let window = UIApplication.shared.windows.first { $0.isKeyWindow }
		return window ?? ASPresentationAnchor()
#else
		return ASPresentationAnchor()
#endif
	}
}

fileprivate extension URL {
	func getQueryStringParameter(_ parameter: String) -> String? {
		guard let url = URLComponents(string: self.absoluteString) else { return nil }
		return url.queryItems?.first(where: { $0.name == parameter })?.value
	}
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey {
	
	func toSecKey() throws -> SecKey {
		var errorQ: Unmanaged<CFError>?
		guard let sf = SecKeyCreateWithData(Data() as NSData, [
			kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeyClass: kSecAttrKeyClassPrivate,
			kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
			"toid": dataRepresentation
		] as NSDictionary, &errorQ) else { throw errorQ!.takeRetainedValue() as Error }
		return sf
	}
}

extension P256.KeyAgreement.PrivateKey {
	func toSecKey() throws -> SecKey {
		var error: Unmanaged<CFError>?
		guard let privateKey = SecKeyCreateWithData(x963Representation as NSData, [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, &error) else {
			throw error!.takeRetainedValue() as Error
		}
		return privateKey
	}
}


public enum OpenId4VCIError: LocalizedError {
	case authRequestFailed(Error)
	case authorizeResponseNoUrl
	case authorizeResponseNoCode
	case tokenRequestFailed(Error)
	case tokenResponseNoData
	case tokenResponseInvalidData(String)
	case dataNotValid
	
	public var localizedDescription: String {
		switch self {
		case .authRequestFailed(let error):
			if let wae = error as? ASWebAuthenticationSessionError, wae.code == .canceledLogin { return "The login has been canceled." }
			return "Authorization request failed: \(error.localizedDescription)"
		case .authorizeResponseNoUrl:
			return "Authorization response does not include a url"
		case .authorizeResponseNoCode:
			return "Authorization response does not include a code"
		case .tokenRequestFailed(let error):
			return "Token request failed: \(error.localizedDescription)"
		case .tokenResponseNoData:
			return "No data received as part of token response"
		case .tokenResponseInvalidData(let reason):
			return "Invalid data received as part of token response: \(reason)"
		case .dataNotValid:
			return "Issued data not valid"
		}
	}
}


