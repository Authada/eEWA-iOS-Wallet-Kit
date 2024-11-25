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
//  JWTAuthenticator.swift
//  EudiWalletKit
//

import Foundation
import JSONWebToken
import JSONWebSignature

public enum IssuerTrustResult: Equatable {
  case success
  case failure(String)
  case unknown(String)
}


public class JWTAuthenticator: NSObject {
    var jwtString: String
    var trustedCerts: [NSData]
    var jws: JWS?
    
    init(jwtString: String, trustedCerts: [NSData]) {
        self.jwtString = jwtString
        self.trustedCerts = trustedCerts
        self.jws = try? JWS(jwsString: jwtString)
    }
    
    public func validateIssuerTrust(subject: String) throws -> IssuerTrustResult {

        let validJWT = verifyJWT()
        let validCertificateCain = validateCertificateChain()
        let validSubject = valdidateSubject(subject: subject)
        
        if !validJWT {
            return .failure("invalid issuer signature")
        }
        
        if !validCertificateCain {
            return .failure("invalid certificate chain")
        }
        
        if !validSubject {
            return .failure("invalid subject")
        }
        
        return .success
    }
    
    internal func verifyJWT() -> Bool {
        let header = jws?.protectedHeader.jwk
        guard let valid =  try? jws?.verify(key: header) else {
            return false
        }
        return valid
    }
    
    internal func validateCertificateChain() -> Bool {
        
        guard let jwtCert = fetchCertificateChain() else {
            return false
        }
        
        let trustedCertificates = trustedCerts.compactMap {
            SecCertificateCreateWithData(nil, $0 as CFData)
        }
        
        if trustedCertificates.isEmpty {
            return false
        }
        
        // Create a certificate trust object
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        
        // Set the certificate chain and policy for trust evaluation
        SecTrustCreateWithCertificates(jwtCert as CFTypeRef, policy, &trust)
        SecTrustSetAnchorCertificates(trust!, trustedCertificates as CFArray)
        
        // Evaluate the trust
        var secTrustError: CFError?
        let evaluateResult = SecTrustEvaluateWithError(trust!, &secTrustError)
        guard !evaluateResult
        else
        {
            return true
        }
        
        return false
    }
    
    
   internal func valdidateSubject(subject: String?) -> Bool {
        
        if let subjectString = fetchSubject(), subjectString == subject{
            return true
        }
        return false
    }
    
    private func fetchCertificateChain() -> [SecCertificate]? {
        do {
            let header = jws?.protectedHeader.jwk
            guard let x5c = header?.x509CertificateChain else {
                return nil
            }
            
            let certificates = try convertStringsToData(
                base64Strings: x5c
            ).compactMap {
                SecCertificateCreateWithData(nil, $0 as CFData)
            }
            return certificates
            
        } catch {
            print(error)
            return nil
        }
    }
    
    private func fetchSubject() -> String? {
        guard let payLoadData = jws?.payload else {
            return nil
        }
        
        if let object = try? JSONSerialization.jsonObject(with: payLoadData) as? [String: Any] {
            if let subjectString = object["sub"] as? String
            {
                print(subjectString)
                return subjectString as String
            }
        }
        
        return nil
    }
    
    func convertStringsToData(base64Strings: [String]) throws -> [Data] {
        var dataObjects: [Data] = []
        for base64String in base64Strings {
            if let data = Data(base64Encoded: base64String) {
                var finalData = data
                if let string = String(data: data, encoding: .utf8) {
                    let shortCert = string.removeCertificateDelimiters()
                    if let encodedData = Data(base64Encoded: shortCert) {
                        finalData = encodedData
                    }
                }
                dataObjects.append(finalData)
            } else {
                
            }
        }
        
        return dataObjects
    }
}
