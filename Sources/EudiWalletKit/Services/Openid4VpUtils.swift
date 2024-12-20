/*
 *  Copyright (c) 2023-2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Modified by AUTHADA GmbH
 *  Copyright (c) 2024 AUTHADA GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import Foundation
import SwiftCBOR
import CryptoKit
import Logging
import PresentationExchange
import MdocDataModel18013
import MdocSecurity18013
/**
 *  Utility class to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = nil,
 *  EReaderKeyBytes = nil
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = Data
 *  responseUriHash = Data
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = String
 *  clientId = String
 *  responseUri = String
 *  nonce = String
 *
 */

class Openid4VpUtils {
	
	static func generateSessionTranscript(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> SessionTranscript {
		let openID4VPHandover = generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri,	nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce)
		return SessionTranscript(handOver: openID4VPHandover)
	}
	
	static func generateOpenId4VpHandover(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> CBOR {
		let clientIdToHash = CBOR.encodeArray([clientId, mdocGeneratedNonce])
		let responseUriToHash = CBOR.encodeArray([responseUri, mdocGeneratedNonce])
		
		let clientIdHash = [UInt8](SHA256.hash(data: clientIdToHash))
		let responseUriHash = [UInt8](SHA256.hash(data: responseUriToHash))
		
		return CBOR.array([.byteString(clientIdHash), .byteString(responseUriHash), .utf8String(nonce)])
	}
	
	static func generateMdocGeneratedNonce() -> String {
		var bytes = [UInt8](repeating: 0, count: 16)
		let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
		if result != errSecSuccess {
			logger.warning("Problem generating random bytes with SecRandomCopyBytes")
			bytes = (0 ..< 16).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) }
		}
		return Data(bytes).base64URLEncodedString()
	}
	
    private static func firstCompatibleFormatFromFormatContainer(fc:FormatContainer) -> String? {
        let orderedCompatibleFormats = ["mso_mdoc", "vc+sd-jwt"]
        for allowedFormat in orderedCompatibleFormats {
            if fc.formats.contains(where: { $0["designation"].string?.lowercased() == allowedFormat}) {
                return allowedFormat
            }
        }
        return nil
    }
    
    internal static func vctFilterDocTypes(inDesc:InputDescriptor) -> [String]? {
        let fields = inDesc.constraints.fields
        var vctField :Field? = nil
        for field in fields {
            if field.paths.contains("$.vct") {
                vctField = field
                break
            }
        }
        if let vctField, let filter = vctField.filter, filter["type"] as? String == "string" {
            if let enumValue = filter["enum"] as? [String] {
                return enumValue
            }
            else if let constValue = filter["const"] as? String {
                return [constValue]
            }
        }
        return nil
    }
    
	/// Parse request from presentation definition (Presentation Exchange 2.0.0 protocol)
    static func parsePresentationDefinition(_ presentationDefinition: PresentationDefinition, logger: Logger? = nil) throws -> RequestedDocumentFormatItems? {
		var res = RequestedDocumentFormatItems()
		for inputDescriptor in presentationDefinition.inputDescriptors {
			guard let fc = inputDescriptor.formatContainer else { logger?.warning("Input descriptor with id \(inputDescriptor.id) is invalid "); continue }
            
            let format = firstCompatibleFormatFromFormatContainer(fc: fc)
            
            guard let format else {
                logger?.warning("Input descriptor with id \(inputDescriptor.id) does not contain supported format (e.g. mso_mdoc or vc+sd-jwt)");
                continue
            }
            
			let identifierAndMdocType = inputDescriptor.id.trimmingCharacters(in: .whitespacesAndNewlines)
            let kvs: [(String, String)]
            let allowedDocTyps: [String]
            
            let dataFormat :DataFormat
            if (format == "vc+sd-jwt") {
                dataFormat = .sdjwt
                let pathRx = try NSRegularExpression(pattern: "\\$\\.(.+)", options: .caseInsensitive)
                let vctFilterDocTypes = vctFilterDocTypes(inDesc: inputDescriptor)
                if let vctFilterDocTypes {
                    allowedDocTyps = vctFilterDocTypes
                }
                else {
                    //Fallback to id
                    allowedDocTyps = [identifierAndMdocType]
                }
                kvs = inputDescriptor.constraints.fields.compactMap(\.paths.first).compactMap { Self.extractSdJwtField($0, docType:identifierAndMdocType, pathRx: pathRx) }
            }
            else {
                //(format == "mso_mdoc")
                dataFormat = .cbor
                let pathRx = try NSRegularExpression(pattern: "\\$\\['([^']+)'\\]\\['([^']+)'\\]", options: .caseInsensitive)
                allowedDocTyps = [identifierAndMdocType]
                kvs = inputDescriptor.constraints.fields.compactMap(\.paths.first).compactMap { Self.extractMdocField($0, pathRx: pathRx) }
            }
	
			let nsItems = Dictionary(grouping: kvs, by: \.0).mapValues { $0.map(\.1) }
            
            let details = RequestedDocumentDetails(allowedDocTypes: allowedDocTyps, fields: nsItems)
            
            if !nsItems.isEmpty { res[identifierAndMdocType] = [dataFormat:details] }
		}
		return res
	}
    

	static func extractMdocField(_ path: String, pathRx: NSRegularExpression) -> (String, String)? {
		guard let match = pathRx.firstMatch(in: path, options: [], range: NSRange(location: 0, length: path.utf16.count)) else { return nil }
		let r1 = match.range(at:1);
		let r1l = path.index(path.startIndex, offsetBy: r1.location)
		let r1r = path.index(r1l, offsetBy: r1.length)
		let r2 = match.range(at: 2)
		let r2l = path.index(path.startIndex, offsetBy: r2.location)
		let r2r = path.index(r2l, offsetBy: r2.length)
		return (String(path[r1l..<r1r]), String(path[r2l..<r2r]))
	}
    
    static func extractSdJwtField(_ path: String, docType:String, pathRx: NSRegularExpression) -> (String, String)? {
        guard let match = pathRx.firstMatch(in: path, options: [], range: NSRange(location: 0, length: path.utf16.count)) else { return nil }
        let r1 = match.range(at:1);
        let r1l = path.index(path.startIndex, offsetBy: r1.location)
        let r1r = path.index(r1l, offsetBy: r1.length)
        return (docType, String(path[r1l..<r1r]))
    }
	
}

extension ECCurveType {
	init?(crvName: String) {
		switch crvName {
		case "P-256": self = .p256
		case "P-384": self = .p384
		case "P-512": self = .p521
		default: return nil
		}
	}
}
