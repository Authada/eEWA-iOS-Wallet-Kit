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
//  ProxyPidDocument.swift
//  

import Foundation
import MdocDataModel18013
import WalletStorage
import PresentationExchange

public struct ProxyPidDocument : WalletDocument {
    
    public static let proxyTagID: String = "proxy"
    public static let proxyPidSupportedDocTypes = [DocumentManager.euPidDocTypeMdoc, DocumentManager.euPidDocTypeSdjwt, "https://example.bmi.bund.de/credential/pid/1.0", "https://metadata-8c062a.usercontent.opencode.de/pid.json"]
    
    //MARK: -
    
    public var id: String {
        return ProxyPidDocument.proxyTagID
    }
    public var createdAt: Date
    public var docTypes = ProxyPidDocument.proxyPidSupportedDocTypes
    public var docFormat: DataFormat? {
        return nil
    }
    
    public var displayStrings: [NameValue] {
        return []
    }
    public var displayImages: [NameImage] {
        return []
    }
    
    //MARK: -
    
    private var mdoc :MdocDecodable?
    internal private(set) var storageDocument :WalletStorage.Document?
    
    init() {
        createdAt = Date()
        if let doc = buildProxyDocument(), let proxyMdoc = toMdocModel(doc: doc) {
            storageDocument = doc
            mdoc = proxyMdoc
        }
    }
    
    //MARK: - Functions
    
    public func getBearersName() -> (first: String, last: String)? {
        return nil
    }
    
    public func getPortraitImageData() -> Data? {
        return nil
    }
    
    public func expiryDateValue() -> String? {
        return nil
    }
    
    //MARK: - Build Proxy
    
    private func toMdocModel(doc: WalletStorage.Document) -> (any MdocDecodable)? {
        guard let (iss, dpk) = doc.getCborData() else {
            return nil
        }
        return GenericMdocModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, title: doc.docType.translated())
    }
    
    private func buildProxyDocument() -> WalletStorage.Document? {
        let issuerSigned = "ompuYW1lU3BhY2VzoXgYZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xmCbYGFhcpGhkaWdlc3RJRABmcmFuZG9tUEzIy/4QVO6iMGjYkqnzFnFxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZWxlbGVtZW50VmFsdWVO2QPsajIyMDAtMDEtMDHYGFhQpGhkaWdlc3RJRAFmcmFuZG9tUPfUURlXzhFGu/m0iF09ZIhxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMThsZWxlbWVudFZhbHVlQfTYGFhfpGhkaWdlc3RJRAJmcmFuZG9tUOPCE8w/9vfbztfewmBRO/NxZWxlbWVudElkZW50aWZpZXJtaXNzdWFuY2VfZGF0ZWxlbGVtZW50VmFsdWVO2QPsajIyMDAtMDEtMDHYGFhRpGhkaWdlc3RJRANmcmFuZG9tUMXJ3fYzKEYtncDQ+nZsWcpxZWxlbWVudElkZW50aWZpZXJrbmF0aW9uYWxpdHlsZWxlbWVudFZhbHVlQmFE2BhYV6RoZGlnZXN0SUQEZnJhbmRvbVAZ3gxOvUt2QNi8urPKB8f+cWVsZW1lbnRJZGVudGlmaWVycWZhbWlseV9uYW1lX2JpcnRobGVsZW1lbnRWYWx1ZUJhRNgYWFGkaGRpZ2VzdElEBWZyYW5kb21QXUH7oRZR2oq9oq1kt7Pub3FlbGVtZW50SWRlbnRpZmllcmtiaXJ0aF9wbGFjZWxlbGVtZW50VmFsdWVCYUTYGFhTpGhkaWdlc3RJRAZmcmFuZG9tUJNWiptjZp5TZmfRh3RMkr9xZWxlbWVudElkZW50aWZpZXJtcmVzaWRlbnRfY2l0eWxlbGVtZW50VmFsdWVCYUTYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUMSTLBfIw5NFYgy134GxKo1xZWxlbWVudElkZW50aWZpZXJucmVzaWRlbnRfc3RhdGVsZWxlbWVudFZhbHVlQmFE2BhYVaRoZGlnZXN0SUQIZnJhbmRvbVCvpRL/dsFLCuqq8a7AlbEqcWVsZW1lbnRJZGVudGlmaWVyb3Jlc2lkZW50X3N0cmVldGxlbGVtZW50VmFsdWVCYUTYGFhWpGhkaWdlc3RJRAlmcmFuZG9tUBMTWP9WibK1HT2+A3f/Hq9xZWxlbWVudElkZW50aWZpZXJwcmVzaWRlbnRfYWRkcmVzc2xlbGVtZW50VmFsdWVCYUTYGFhapGhkaWdlc3RJRApmcmFuZG9tUMoJ9QjH6fWs1YBePIwb3CNxZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGVsZWxlbWVudFZhbHVlQmFE2BhYVqRoZGlnZXN0SUQLZnJhbmRvbVDcebhyRQzlNoCag5lbG0ejcWVsZW1lbnRJZGVudGlmaWVycHJlc2lkZW50X2NvdW50cnlsZWxlbWVudFZhbHVlQmFE2BhYXaRoZGlnZXN0SUQMZnJhbmRvbVCITS2N4BdCL5oqmbJ1H+4mcWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZU7ZA+xqMjIwMC0wMS0wMdgYWFOkaGRpZ2VzdElEDWZyYW5kb21QHmve3kUg5Q0LXm9Wvs7/L3FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVEVEVTVNgYWFKkaGRpZ2VzdElEDmZyYW5kb21QO+mgp9zL34LnrXNpfsn1PnFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZURURVNU2BhYUaRoZGlnZXN0SUQPZnJhbmRvbVDIt+RsPKmSJuug5/yxRzjncWVsZW1lbnRJZGVudGlmaWVyaWJpcnRoZGF0ZWxlbGVtZW50VmFsdWVEVEVTVNgYWFekaGRpZ2VzdElEEGZyYW5kb21Q+wCR14ArtJe7Rg1leXbLK3FlbGVtZW50SWRlbnRpZmllcnFhZ2VfZXF1YWxfb3Jfb3ZlcmxlbGVtZW50VmFsdWVCMTjYGFhcpGhkaWdlc3RJRBFmcmFuZG9tUL0z2BI9xZR97XAPYQfn73RxZWxlbWVudElkZW50aWZpZXJ0YWdlX2VxdWFsX29yX292ZXIuMThsZWxlbWVudFZhbHVlRHRydWXYGFhRpGhkaWdlc3RJRBJmcmFuZG9tUNbLWqpo6MIMwhxd8WkNLelxZWxlbWVudElkZW50aWZpZXJjaWF0bGVsZW1lbnRWYWx1ZUoxOTkwLTAxLTAx2BhYVqRoZGlnZXN0SUQTZnJhbmRvbVCg5jIcR4NfFsHj7xj2cRJUcWVsZW1lbnRJZGVudGlmaWVybmFnZV9iaXJ0aF95ZWFybGVsZW1lbnRWYWx1ZUQxOTkw2BhYVKRoZGlnZXN0SUQUZnJhbmRvbVB4MBYAIqJajCcUWt1mDClgcWVsZW1lbnRJZGVudGlmaWVybGFnZV9pbl95ZWFyc2xlbGVtZW50VmFsdWVEMTk5MNgYWFKkaGRpZ2VzdElEFWZyYW5kb21QWfteInmzaQofMLREPQZ9HHFlbGVtZW50SWRlbnRpZmllcm1uYXRpb25hbGl0aWVzbGVsZW1lbnRWYWx1ZUFE2BhYWaRoZGlnZXN0SUQWZnJhbmRvbVD8qihSDaf6Ktqy12j+tYXtcWVsZW1lbnRJZGVudGlmaWVycWJpcnRoX2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZURURVNU2BhYVqRoZGlnZXN0SUQXZnJhbmRvbVCVfl4Crj2ClV0P8XLbxS3tcWVsZW1lbnRJZGVudGlmaWVybnBsYWNlX29mX2JpcnRobGVsZW1lbnRWYWx1ZURURVNU2BhYYKRoZGlnZXN0SUQYGGZyYW5kb21QXE/lGtShDCjZDlxrrnQaw3FlbGVtZW50SWRlbnRpZmllcndwbGFjZV9vZl9iaXJ0aC5sb2NhbGl0eWxlbGVtZW50VmFsdWVEVEVTVNgYWF6kaGRpZ2VzdElEGBlmcmFuZG9tUIMzEbCulkz3c0P7D8rK9GZxZWxlbWVudElkZW50aWZpZXJ1cGxhY2Vfb2ZfYmlydGgucmVnaW9ubGVsZW1lbnRWYWx1ZURURVNU2BhYX6RoZGlnZXN0SUQYGmZyYW5kb21QlQnqT8wMAmRHAeknuDhXK3FlbGVtZW50SWRlbnRpZmllcnZwbGFjZV9vZl9iaXJ0aC5jb3VudHJ5bGVsZW1lbnRWYWx1ZURURVNU2BhYUKRoZGlnZXN0SUQYG2ZyYW5kb21QhPOD5XoemnR1NyqkrH4e43FlbGVtZW50SWRlbnRpZmllcmdhZGRyZXNzbGVsZW1lbnRWYWx1ZURURVNU2BhYWqRoZGlnZXN0SUQYHGZyYW5kb21Q0A6TOuGEAbYVGsESpcmXNXFlbGVtZW50SWRlbnRpZmllcnFhZGRyZXNzLmZvcm1hdHRlZGxlbGVtZW50VmFsdWVEVEVTVNgYWFikaGRpZ2VzdElEGB1mcmFuZG9tUMH6L80KwwXzsmJ3glkv4wRxZWxlbWVudElkZW50aWZpZXJvYWRkcmVzcy5jb3VudHJ5bGVsZW1lbnRWYWx1ZURURVNU2BhYV6RoZGlnZXN0SUQYHmZyYW5kb21Q+ns7lgm/pzpJWRMnbecPp3FlbGVtZW50SWRlbnRpZmllcm5hZGRyZXNzLnJlZ2lvbmxlbGVtZW50VmFsdWVEVEVTVNgYWFmkaGRpZ2VzdElEGB9mcmFuZG9tUFfNthHq1/YZAjBvLRUePJBxZWxlbWVudElkZW50aWZpZXJwYWRkcmVzcy5sb2NhbGl0eWxlbGVtZW50VmFsdWVEVEVTVNgYWFykaGRpZ2VzdElEGCBmcmFuZG9tUPBObh4iZxai9sncU1py/IRxZWxlbWVudElkZW50aWZpZXJzYWRkcmVzcy5wb3N0YWxfY29kZWxlbGVtZW50VmFsdWVEVEVTVNgYWF+kaGRpZ2VzdElEGCFmcmFuZG9tUH0fz1gu506IzBkJtP/Pb4JxZWxlbWVudElkZW50aWZpZXJ2YWRkcmVzcy5zdHJlZXRfYWRkcmVzc2xlbGVtZW50VmFsdWVEVEVTVNgYWFKkaGRpZ2VzdElEGCJmcmFuZG9tUGgGmDXSsh5JVt/FAx7TA59xZWxlbWVudElkZW50aWZpZXJjZXhwbGVsZW1lbnRWYWx1ZUoyMjAwLTAxLTAx2BhYVqRoZGlnZXN0SUQYI2ZyYW5kb21QauaOdRR0mtZqjBkVpeNPKXFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlQkRF2BhYWKRoZGlnZXN0SUQYJGZyYW5kb21QwcLAuHY3cLyykho2NDluRnFlbGVtZW50SWRlbnRpZmllcnFpc3N1aW5nX2F1dGhvcml0eWxlbGVtZW50VmFsdWVCREXYGFhbpGhkaWdlc3RJRBglZnJhbmRvbVCPN9M3OLUfxoPfHhjXQHyjcWVsZW1lbnRJZGVudGlmaWVydHNvdXJjZV9kb2N1bWVudF90eXBlbGVsZW1lbnRWYWx1ZUJERWppc3N1ZXJBdXRohEOhASahGCGAWQae2BhZBpmmZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6F4GGV1LmV1cm9wYS5lYy5ldWRp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"
        let privateKey = "pQECIAEhWCBoHIiBQnDRMLUT4yOLqJ1l8mrfNIgrjNnFq4RyZgxSmiJYIGD/Sabu6GejaR4eTiym1JkyjnBNcJ+f59pN+lCEyhVyI1ggC6EPCKyGci++LGWUX3fXpPFW6pYO8pyyKLMKs1qF0jo="
        
        guard let data = Data(base64URLEncoded: issuerSigned) else {
            return nil
        }
        guard let keyData = CoseKeyPrivate(base64: privateKey) else {
            return nil
        }
        let proxy = WalletStorage.Document.init(id: ProxyPidDocument.proxyTagID ,docType: DocumentManager.euPidDocTypeMdoc, docDataType: .cbor, data: data, privateKeyType: .x963EncodedP256, privateKey: keyData.getx963Representation(), createdAt: Date())
        return proxy
    }
    
    //MARK: - Helper Methods
    
    internal static func firstProxyPidDocTypeMatching(inputDescritor: InputDescriptor) -> String? {
        let proxyPidTypes = ProxyPidDocument.proxyPidSupportedDocTypes
        if let vctDocTypes = Openid4VpUtils.vctFilterDocTypes(inDesc: inputDescritor) {
            for vctDocType in vctDocTypes {
                if proxyPidTypes.contains(vctDocType) {
                    return vctDocType
                }
            }
        }
        //No vct value match - try inputDescritor.id used by mDoc
        if (proxyPidTypes.contains(inputDescritor.id)) {
            return inputDescritor.id
        }
        return nil
    }
}
