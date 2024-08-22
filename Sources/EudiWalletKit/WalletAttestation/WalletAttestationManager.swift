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
//  WalletAttestationManager.swift
//  

import Foundation
import DeviceCheck
import CryptoKit
import JOSESwift
import OpenID4VCI

private let APP_ATTESTATION_KEY_ID_PREF_KEY = "APP_ATTESTATION_KEY_ID"
private let WALLET_ATTESTATION_KEY_DATA_PREF_KEY = "WALLET_ATTESTATION_KEY_DATA"

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

public class WalletAttestationManager {
        
    private var cachedCNonce :String? = nil
    private var cachedAppAttestationKeyId :String? = nil
    private var cachedWalletAttestationKeyData :Data? = nil
    
    private var walletAttestationJwsString :String? = nil
    
    private let walletHostURL = EudiWallet.standard.walletAttestationHostUrl ?? ""
    private let walletClientID = EudiWallet.standard.walletAttestationClientId ?? ""
    
    private let appAttestService :DCAppAttestService? = {
        let service = DCAppAttestService.shared
        if service.isSupported {
            return service
        }
        return nil
    }()
    
    public init() {
        //TODO: muss ich public sein???
    }
    
    //MARK: Reset Data
    
    private func resetWalletAttestationKeyData() {
        cachedWalletAttestationKeyData = nil
        UserDefaults.standard.removeObject(forKey: WALLET_ATTESTATION_KEY_DATA_PREF_KEY)
    }
    
    private func resetWalletAttestationData() {
        walletAttestationJwsString = nil
        cachedCNonce = nil
    }
    
    private func resetAppAttestationReleatedData() {
        resetWalletAttestationData()
        UserDefaults.standard.removeObject(forKey: APP_ATTESTATION_KEY_ID_PREF_KEY)
        cachedAppAttestationKeyId = nil
    }
    
    
    //MARK: - Client Assertion
    
    private func walletAttestationClientAssertionValue(cnonce:String, audience:String) async throws -> String {
        let walletAttestationJWS = try await walletAttestationJWS()
        let popJWS = try await walletAttestationPopJWS(cnonce: cnonce, audience: audience)
        let clientAssertionValue = walletAttestationJWS + "~" + popJWS
        return clientAssertionValue
    }
    
    public func clientAssertion(cnonce:String, audience:String) async throws -> ClientAssertion {
        let clientAssertionValue = try await walletAttestationClientAssertionValue(cnonce: cnonce, audience: audience)
        
        let clientAssertion = ClientAssertion(value: clientAssertionValue, type: "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation")
        return clientAssertion
    }
    
    //MARK: - Wallet Attestation POP
    
    public func walletAttestationPopJWS(cnonce:String, audience:String) async throws -> String {
        
        let key = try walletAttestationSecKey()
        
        let sigAlgorithm :SignatureAlgorithm = .ES256
        
        //Header
        let header = JWSHeader(algorithm: sigAlgorithm)

        //Payload
        let clientID = walletClientID
        let walletAttPopData = WalletAttestationPopData(issuer: clientID, audience: audience, nonce: cnonce, issuedAt: Date(), expirationTime: Date(timeIntervalSinceNow: 300.0))
        let payloadData = try JSONEncoder().encode(walletAttPopData)
        let payload = Payload(payloadData)
        
        //Signer
        let signer = Signer(signingAlgorithm: sigAlgorithm, key: key)!
        
        //build JWS
        let jws = try JWS(header: header, payload: payload, signer: signer)

        let jwsString = jws.compactSerializedString
        
        return jwsString
    }
    
    //MARK: - Wallet Attestation
    
    public func walletAttestationJWS() async throws -> String {
        if let walletAtt = walletAttestationJwsString {
            return walletAtt
        }
        
        let walletAtt = try await createWalletAttestation()
        walletAttestationJwsString = walletAtt
        return walletAtt
    }
    
    private func createWalletAttestation() async throws -> String {
        
        resetWalletAttestationData()
        
        let appAttestation = try await performAppAttestation()
        let secKey = try walletAttestationSecKey()

        let walletAttString = try await receiveWalletAttestation(appAttesttaion: appAttestation, privateKey: secKey)
        
        return walletAttString
    }
    
    //MARK: - Wallet Attestation Key
    
    private func walletAttestationSecKey() throws -> SecKey {
        if let key = loadWalletAttestationKey() {
            //print("test \(key)")
            let secKey = try key.toSecKey()
            return secKey
        }
        else {
            throw WalletError(description: "loading wallet attestation key failed")
        }
    }
    
    private func loadWalletAttestationKey() -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
        
        var key : SecureEnclave.P256.KeyAgreement.PrivateKey? = nil
        
        if (cachedWalletAttestationKeyData == nil) {
            cachedWalletAttestationKeyData = UserDefaults.standard.data(forKey: WALLET_ATTESTATION_KEY_DATA_PREF_KEY)
        }
        
        if let keyData = cachedWalletAttestationKeyData {
            do {
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
            }
            catch {
                resetWalletAttestationKeyData()
            }
        }
        
        if (key == nil) {
            do {
                let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
                key = seKey
                cachedWalletAttestationKeyData = seKey.dataRepresentation
                UserDefaults.standard.setValue(cachedWalletAttestationKeyData, forKey: WALLET_ATTESTATION_KEY_DATA_PREF_KEY)
            }
            catch {
                print("error create wallet att key: \(error)")
                return nil
            }
        }
        
        return key
    }
    
    //MARK: - Wallet Attestation
    
    private func buildWalletAttesationMessageData(appAttesttaion:Data, privateKey:SecKey) throws -> Data {
        
        guard let nonce = cachedCNonce else {
            throw WalletError(description: "Wallet attestation nonce missing")
        }
        
        let sigAlgorithm :SignatureAlgorithm = .ES256
                
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw WalletError(description: "Failed to generate public key for wallet attestation")
        }
        
        //Header
        let jwk = try ECPublicKey(publicKey: publicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString])
        
        var header = JWSHeader(algorithm: sigAlgorithm)
        header.typ = "wallet-proof+jwt"
        header.jwkTyped = jwk
        
        //Payload
        let appAttData = AppAttestationData(attestation: appAttesttaion.base64EncodedString())
        let clientID = walletClientID
        let walletAttReqData = WalletAttestationRequestData(issuer: clientID, audience: walletHostURL, appAttestation: appAttData, nonce: nonce, issuedAt: Date())
        let payloadData = try JSONEncoder().encode(walletAttReqData)
        let payload = Payload(payloadData)
        
        //Signer
        let signer = Signer(signingAlgorithm: sigAlgorithm, key: privateKey)!
        
        //build JWS
        let jws = try JWS(header: header, payload: payload, signer: signer)

        let jwsString = jws.compactSerializedString
        
        //Proof
        let proofData = ProofData(jwt: jwsString)
        let proof = Proof(proofData: proofData)
        
        let messageData = try JSONEncoder().encode(proof)
        
        return messageData
    }
    
    private func receiveWalletAttestation(appAttesttaion:Data, privateKey:SecKey) async throws -> String {
        
        let messageData = try buildWalletAttesationMessageData(appAttesttaion: appAttesttaion, privateKey: privateKey)
        
        if let walletURL = URL(string: walletHostURL) {
            let attestationURL = walletURL.appendingPathComponent("attestation")
            let urlSession = URLSession.shared
            var urlRequest = URLRequest(url: attestationURL, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
            urlRequest.httpMethod = "POST"
            urlRequest.httpBody = messageData
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
            do {
                let result = try await urlSession.data(for: urlRequest)
                
                let data = result.0
                if let response = result.1 as? HTTPURLResponse, response.statusCode == 200, response.mimeType?.lowercased() == "application/json" {

                    let jsonData = try JSONDecoder().decode(WalletAttestationData.self, from: data)
                    if let walletAttestationJwsString = jsonData.attestation {
                        return walletAttestationJwsString
                    }
                    else {
                        throw WalletError(description: "Wallet attestation not found in received data")
                    }
                }
                else {
                    throw WalletError(description: "Failed to fetch wallet attestation")
                }
            }
            catch {
                throw WalletError(description: "Failed to fetch wallet attestation: \(error.localizedDescription)")
            }
        }
        throw WalletError(description: "Error: Invalid wallet host url")
    }
    
    //MARK: - App Attestation
    
    public func isAppAttestationSupported() -> Bool {
        return appAttestService != nil
    }
    
    private func performAppAttestation(allowKeyReset: Bool = true) async throws -> Data  {
        guard let appAttestService, let keyId = try await keyIdForAppAttestation()
        else {
            throw WalletError(description: "app attestation not supported")
        }
        
        let challenge = try await receiveNewChallenge()
        let hash = Data(SHA256.hash(data: challenge))
        
        do {
            let attestation = try await appAttestService.attestKey(keyId, clientDataHash: hash)
            return attestation
        }
        catch {
            if let err = error as? DCError, err.code == .invalidKey, allowKeyReset {
                resetAppAttestationReleatedData()
                return try await performAppAttestation(allowKeyReset: false)
            }
            throw WalletError(description: "creating app attestation failed: \(error.localizedDescription)")
        }
    }
    
    private func keyIdForAppAttestation() async throws -> String? {
        if cachedAppAttestationKeyId == nil {
            guard let appAttestService else { return nil }
            
            cachedAppAttestationKeyId = UserDefaults.standard.string(forKey: APP_ATTESTATION_KEY_ID_PREF_KEY)
            
            if cachedAppAttestationKeyId == nil {
                do {
                    let keyIdentifier = try await appAttestService.generateKey()
                    cachedAppAttestationKeyId = keyIdentifier
                    UserDefaults.standard.setValue(keyIdentifier, forKey: APP_ATTESTATION_KEY_ID_PREF_KEY)
                }
                catch {
                    throw WalletError(description: "creating app attestation key failed: \(error.localizedDescription)")
                }
            }
        }
        return cachedAppAttestationKeyId
    }
    
    //MARK: - Challenge
    
    private func receiveNewChallenge() async throws -> Data {
        cachedCNonce = nil
        if let walletURL = URL(string: walletHostURL) {
            let nonceURL = walletURL.appendingPathComponent("cnonce")
            let urlSession = URLSession.shared
            do {
                let result = try await urlSession.data(from: nonceURL)
                
                let data = result.0
                if let response = result.1 as? HTTPURLResponse, response.statusCode == 200, response.mimeType?.lowercased() == "application/json" {

                    let jsonData = try JSONDecoder().decode(CNonceData.self, from: data)
                    if let nonce = jsonData.cNonce, let nonceData = nonce.data(using: .utf8) {
                        cachedCNonce = nonce
                        return nonceData
                    }
                }
            }
            catch {
                throw WalletError(description: "Failed to fetch app attestation challenge: \(error.localizedDescription)")
            }
        }
        throw WalletError(description: "Failed to fetch app attestation challenge")
    }
}
