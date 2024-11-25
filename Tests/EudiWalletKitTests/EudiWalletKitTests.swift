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

import XCTest
@testable import EudiWalletKit
import Foundation
import CryptoKit
import PresentationExchange
import MdocDataModel18013
import SwiftCBOR

final class EudiWalletKitTests: XCTestCase {
    
    func testParsePresentationDefinition() throws {
        let testPD = try JSONDecoder().decode(PresentationDefinition.self, from: Data(name: "TestPresentationDefinition", ext: "json", from: Bundle.module)! )
        let items = try XCTUnwrap(Openid4VpUtils.parsePresentationDefinition(testPD))
        XCTAssert(!items.keys.isEmpty)
        print(items)
    }
    
    let ANNEX_B_OPENID4VP_HANDOVER = "835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930"
    let ANNEX_B_SESSION_TRANSCRIPT = "83F6F6835820DA25C527E5FB75BC2DD31267C02237C4462BA0C1BF37071F692E7DD93B10AD0B5820F6ED8E3220D3C59A5F17EB45F48AB70AEECF9EE21744B1014982350BD96AC0C572616263646566676831323334353637383930"
    
    let clientId = "example.com"
    let responseUri = "https://example.com/12345/response"
    let nonce = "abcdefgh1234567890"
    let mdocGeneratedNonce = "1234567890abcdefgh"
    let signedMetaData = "eyJ0eXAiOiJpc3N1ZXItYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJqd2siOnsia3R5IjoiRUMiLCJ4NXQjUzI1NiI6Ik5QamdXRXZoY193QTV2S2c5SkdwYnZZUUtxNy0xT2UzLVA4d1FNSTdjV2ciLCJuYmYiOjE3Mjk2NjU3OTgsInVzZSI6InNpZyIsImNydiI6IlAtMjU2Iiwia2lkIjoiaXNzdWVyIHRydXN0bGlzdCBjYSIsIng1YyI6WyJNSUlCampDQ0FUU2dBd0lCQWdJRVp4aWJCakFLQmdncWhrak9QUVFEQWpBWE1SVXdFd1lEVlFRRERBeFVjblZ6ZEV4cGMzUWdRMEV3SGhjTk1qUXhNREl6TURZME16RTRXaGNOTWpreE1ESXpNRFkwTXpFNFdqQWVNUnd3R2dZRFZRUUREQk5KYzNOMVpYSWdWSEoxYzNSTWFYTjBJRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZlhZUitpRngxejVlODB5TmRNSkpEbFoyK0ozUWhaTnVzdHFZbnJPei8zdjI5Um9MU3VOTUkzU3VBZnZPQmNsTUJFdUlwZGVXUTgranlpeVR5WHNhUHFObk1HVXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1COEdBMVVkSXdRWU1CYUFGSXVQeFRXV25zN3QvL0N0eCtSVllNbzJiejZTTUIwR0ExVWREZ1FXQkJUMHg2Y0RYN1FQZ1g1dlJ4WkVyaWcvNTZVekl6QVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBekFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUFpbDJSMGJPRzBhYys0SXcxaXZGREtEeWJJVW9PdmQvdGpiQ0F1WkJxNVJnSWhBUE8wTjh1anNwbGpEMTVTNGRmTTFQcmcxNWJpNFA0ajBUQ01lN3gwOFpyUiJdLCJ4IjoiZlhZUi1pRngxejVlODB5TmRNSkpEbFoyLUozUWhaTnVzdHFZbnJPel8zcyIsInkiOiI5dlVhQzByalRDTjByZ0g3emdYSlRBUkxpS1hYbGtQUG84b3NrOGw3R2o0IiwiZXhwIjoxODg3NDMyMTk4fX0.eyJzdWIiOiJodHRwczovL2lkLmxvY2FsLmNvcnAuYXV0aGFkYS5kZS9ldWRpL2lzc3Vlci9waWQiLCJ0eXBlcyI6WyJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJodHRwczovL2V4YW1wbGUuYm1pLmJ1bmQuZGUvY3JlZGVudGlhbC9waWQvMS4wIiwiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIiwib3JnLmlzby4xODAxMy41LjEubURMIiwidXJuOmV1LmV1cm9wYS5lYy5ldWRpOm1zaXNkbjoxIiwidXJuOmV1LmV1cm9wYS5lYy5ldWRpOmVtYWlsOjEiXSwiaXNzIjoiQVVUSEFEQSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4NXQjUzI1NiI6IkhSaVd4SW9VQmQ5MEVDWDl1dUdRaUh3MFpmNmxkeWNNWFVzWUZsU01qbDgiLCJuYmYiOjE3Mjk2NzMyMDksImNydiI6IlAtMjU2Iiwia2lkIjoiaXNzdWVyLWtleXMiLCJ4NWMiOlsiTUlJQklEQ0J5S0FEQWdFQ0FnUm5HTGY1TUFvR0NDcUdTTTQ5QkFNQ01Ca3hGekFWQmdOVkJBTU1Ea0ZWVkVoQlJFRWdTWE56ZFdWeU1CNFhEVEkwTVRBeU16QTRORFkwT1ZvWERUSTNNVEF5TXpBNE5EWTBPVm93R1RFWE1CVUdBMVVFQXd3T1FWVlVTRUZFUVNCSmMzTjFaWEl3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNQSVpDTjhvVENLcmxEVFdQNjBWVUlacEFBdWZRSjBQeEJVOVgxNFordWFWL0xPaElWL1hLT1I3MDg3RUJaNExob0tFRE5RU2tIcVQzeDR6OU9JeTZ2TUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUh3a1ozZkIxR3NVTTZoR21SMG1FMVMxZE9PV1loQlhtZlk2eDFtc1VhWlhBaUJtNTRlZXVjaWVUMW1oaEttY3hmUEJIY2IxakNUUVhRUGF0dC8vRHdmaUFRPT0iXSwieCI6Imp5R1FqZktFd2lxNVEwMWotdEZWQ0dhUUFMbjBDZEQ4UVZQVjllR2ZybWsiLCJ5IjoiWDhzNkVoWDljbzVIdlR6c1FGbmd1R2dvUU0xQktRZXBQZkhqUDA0akxxOCIsImV4cCI6MTgyNDI4MTIwOX19LCJleHAiOjE4MjYxMDA2MjEsImlhdCI6MTczMTQ5MjYyMX0.kasp4uhW2pL0qkp0M3HLq9JOJFTtrX_piiS4HXT25ppztV9ULl2y_FPAbsrWl1DffX8tWp6ZRy_UnmsO1YPq2g"
    
    let signedMetaDataInvalid = "eyJ0eXAiOiJpc3N1ZXItYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJqd2siOnsia3R5IjoiRUMiLCJ4NXQjUzI1NiI6Ik5QamdXRXZoY193QTV2S2c5SkdwYnZZUUtxNy0xT2UzLVA4d1FNSTdjV2ciLCJuYmYiOjE3Mjk2NjU3OTgsInVzZSI6InNpZyIsImNydiI6IlAtMjU2Iiwia2lkIjoiaXNzdWVyIHRydXN0bGlzdCBjYSIsIng1YyI6WyJNSUlCampDQ0FUU2dBd0lCQWdJRVp4aWJCakFLQmdncWhrak9QUVFEQWpBWE1SVXdFd1lEVlFRRERBeFVjblZ6ZEV4cGMzUWdRMEV3SGhjTk1qUXhNREl6TURZME16RTRXaGNOTWpreE1ESXpNRFkwTXpFNFdqQWVNUnd3R2dZRFZRUUREQk5KYzNOMVpYSWdWSEoxYzNSTWFYTjBJRU5CTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZlhZUitpRngxejVlODB5TmRNSkpEbFoyK0ozUWhaTnVzdHFZbnJPei8zdjI5Um9MU3VOTUkzU3VBZnZPQmNsTUJFdUlwZGVXUTgranlpeVR5WHNhUHFObk1HVXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1COEdBMVVkSXdRWU1CYUFGSXVQeFRXV25zN3QvL0N0eCtSVllNbzJiejZTTUIwR0ExVWREZ1FXQkJUMHg2Y0RYN1FQZ1g1dlJ4WkVyaWcvNTZVekl6QVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBekFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUFpbDJSMGJPRzBhYys0SXcxaXZGREtEeWJJVW9PdmQvdGpiQ0F1WkJxNVJnSWhBUE8wTjh1anNwbGpEMTVTNGRmTTFQcmcxNWJpNFA0ajBUQ01lN3gwOFpyUiJdLCJ4IjoiZlhZUi1pRngxejVlODB5TmRNSkpEbFoyLUozUWhaTnVzdHFZbnJPel8zcyIsInkiOiI5dlVhQzByalRDTjByZ0g3emdYSlRBUkxpS1hYbGtQUG84b3NrOGw3R2o0IiwiZXhwIjoxODg3NDMyMTk4fX0.eyJzdWIiOiJodHRwczovL2lkLmxvY2FsLmNvcnAuYXV0aGFkYS5kZS9ldWRpL2lzc3Vlci9waWQiLCJ0eXBlcyI6WyJ1cm46ZXUuZXVyb3BhLmVjLmV1ZGk6cGlkOjEiLCJodHRwczovL2V4YW1wbGUuYm1pLmJ1bmQuZGUvY3JlZGVudGlhbC9waWQvMS4wIiwiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIiwib3JnLmlzby4xODAxMy41LjEubURMIiwidXJuOmV1LmV1cm9wYS5lYy5ldWRpOm1zaXNkbjoxIiwidXJuOmV1LmV1cm9wYS5lYy5ldWRpOmVtYWlsOjEiXSwiaXNzIjoiQVVUSEFEQSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJ4NXQjUzI1NiI6IkhSaVd4SW9VQmQ5MEVDWDl1dUdRaUh3MFpmNmxkeWNNWFVzWUZsU01qbDgiLCJuYmYiOjE3Mjk2NzMyMDksImNydiI6IlAtMjU2Iiwia2lkIjoiaXNzdWVyLWtleXMiLCJ4NWMiOlsiTUlJQklEQ0J5S0FEQWdFQ0FnUm5HTGY1TUFvR0NDcUdTTTQ5QkFNQ01Ca3hGekFWQmdOVkJBTU1Ea0ZWVkVoQlJFRWdTWE56ZFdWeU1CNFhEVEkwTVRBeU16QTRORFkwT1ZvWERUSTNNVEF5TXpBNE5EWTBPVm93R1RFWE1CVUdBMVVFQXd3T1FWVlVTRUZFUVNCSmMzTjFaWEl3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNQSVpDTjhvVENLcmxEVFdQNjBWVUlacEFBdWZRSjBQeEJVOVgxNFordWFWL0xPaElWL1hLT1I3MDg3RUJaNExob0tFRE5RU2tIcVQzeDR6OU9JeTZ2TUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUh3a1ozZkIxR3NVTTZoR21SMG1FMVMxZE9PV1loQlhtZlk2eDFtc1VhWlhBaUJtNTRlZXVjaWVUMW1oaEttY3hmUEJIY2IxakNUUVhRUGF0dC8vRHdmaUFRPT0iXSwieCI6Imp5R1FqZktFd2lxNVEwMWotdEZWQ0dhUUFMbjBDZEQ4UVZQVjllR2ZybWsiLCJ5IjoiWDhzNkVoWDljbzVIdlR6c1FGbmd1R2dvUU0xQktRZXBQZkhqUDA0akxxOCIsImV4cCI6MTgyNDI4MTIwOX19LCJleHAiOjE4MjYxMDA2MjIsImlhdCI6MTczMTQ5MjYyMX0=.kasp4uhW2pL0qkp0M3HLq9JOJFTtrX_piiS4HXT25ppztV9ULl2y_FPAbsrWl1DffX8tWp6ZRy_UnmsO1YPq2g"
    
    func testGenerateOpenId4VpHandover() {
        let openid4VpHandover = Openid4VpUtils.generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri, nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce)
        XCTAssertEqual(ANNEX_B_OPENID4VP_HANDOVER, openid4VpHandover.encode().toHexString().uppercased())
    }
    
    func testGenerateSessionTranscript() {
        let sessionTranscript = Openid4VpUtils.generateSessionTranscript(clientId: clientId, responseUri: responseUri, nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce).encode(options: CBOROptions())
        XCTAssertEqual(ANNEX_B_SESSION_TRANSCRIPT, sessionTranscript.toHexString().uppercased())
    }
    
    
    func testJWTValdidation() {

        guard let certificateData = Data(name: "issuer_trustlist_ca", ext: "cer", from: Bundle.module) else {
            XCTFail("certificate data could not be loaded")
            return
        }
        let jwtAuth = JWTAuthenticator(jwtString: signedMetaData, trustedCerts: [certificateData as NSData])
        XCTAssertTrue(try jwtAuth.validateIssuerTrust(subject: "https://id.local.corp.authada.de/eudi/issuer/pid") == .success)
    }
    
    func testJWTValdidation_invalid() {
        guard let certificateData = Data(name: "eudi_pid_issuer_ut", ext: "der", from: Bundle.module) else {
            XCTFail("truststore file not loaded")
            return
        }
        
        let jwtAuth = JWTAuthenticator(jwtString: signedMetaData, trustedCerts: [certificateData as NSData])
        XCTAssertFalse(try jwtAuth.validateIssuerTrust(subject: "https://id.local.corp.authada.de/eudi/issuer/pid") == .success)
    }
    
}
