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
import SwiftCBOR
import MdocDataModel18013
import WalletStorage
import Logging
import CryptoKit
import eudi_lib_sdjwt_swift

/// Storage manager. Provides services and view models
public class StorageManager: ObservableObject {
	public static let knownDocTypes = [EuPidModel.euPidDocType, IsoMdlModel.isoDocType]
	/// Array of doc.types of documents loaded in the wallet
    public var docTypes: [[String]] { walletDocuments.map(\.docTypes) }
	/// Array of document models loaded in the wallet
    @Published public var walletDocuments: [any WalletDocument] = []
	@Published internal var mdocModels: [any MdocDecodable] = []
	/// Array of document identifiers loaded in the wallet
	public var documentIds: [String] { walletDocuments.map(\.id) }
	var storageService: any DataStorageService
	/// Whether wallet currently has loaded data
	@Published public var hasData: Bool = false
	/// Whether wallet currently has loaded a document with doc.type included in the ``knownDocTypes`` array
	@Published public var hasWellKnownData: Bool = false
	/// Count of documents loaded in the wallet
	@Published public var docCount: Int = 0
	/// The first driver license model loaded in the wallet (deprecated)
	@Published public var mdlModel: IsoMdlModel?
	/// The first PID model loaded in the wallet (deprecated)
	@Published public var pidModel: EuPidModel?
	/// Error object with localized message
	@Published public var uiError: WalletError?
	let logger: Logger
	
	public init(storageService: any DataStorageService) {
		logger = Logger(label: "\(StorageManager.self)")
		self.storageService = storageService
	}
	
	@MainActor
	func refreshPublishedVars() {
		hasData = walletDocuments.count > 0
        hasWellKnownData = hasData && !Set(docTypes.flatMap{ $0 }).isDisjoint(with: Self.knownDocTypes)
		docCount = walletDocuments.count
		mdlModel = getTypedDoc()
		pidModel = getTypedDoc()
	}
	
	@MainActor
    func refreshWalletDocuments(_ docs: [WalletStorage.Document]) {
        var finalDocuments :[any WalletDocument] = []
        var finalMdocModels :[any MdocDecodable] = []
        
        for doc in docs {
            if doc.docDataType == .sdjwt {
                if let sdjwt = toSdjwt(doc: doc) {
                    let doc = SdjwtDocument(id: doc.id, signedSDJWT: sdjwt, createdAt: doc.createdAt, docType: doc.docType)
                    finalDocuments.append(doc)
                }
            }
            else {
                if let mdoc = toMdocModel(doc: doc) {
                    let doc = MdocDocument(mdoc: mdoc)
                    finalMdocModels.append(mdoc)
                    finalDocuments.append(doc)
                }
            }
        }
        
		mdocModels = finalMdocModels
        walletDocuments = finalDocuments
	}
	
	@MainActor
	@discardableResult func appendDoc(_ doc: WalletStorage.Document) -> WalletDocument? {
        var newDoc :WalletDocument? = nil
        if doc.docDataType == .sdjwt {
            if let sdjwt = toSdjwt(doc: doc) {
                let doc = SdjwtDocument(id: doc.id, signedSDJWT: sdjwt, createdAt: doc.createdAt, docType: doc.docType)
                newDoc = doc
            }
        }
        else {
            if let mdoc = toMdocModel(doc: doc) {
                let doc = MdocDocument(mdoc: mdoc)
                mdocModels.append(mdoc)
                newDoc = doc
            }
        }
        if let newDoc {
            walletDocuments.append(newDoc)
        }
		return newDoc
	}

	func toMdocModel(doc: WalletStorage.Document) -> (any MdocDecodable)? {
        guard let (iss, dpk) = doc.getCborData() else {
            return nil
        }
		return switch doc.docType {
		case EuPidModel.euPidDocType:
            EuPidModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1)!
		case IsoMdlModel.isoDocType:
            IsoMdlModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1)!
		default:
            GenericMdocModel(id: iss.0, createdAt: doc.createdAt, issuerSigned: iss.1, devicePrivateKey: dpk.1, docType: doc.docType, title: doc.docType.translated())
		}
	}
    
    func toSdjwt(doc: WalletStorage.Document) -> SignedSDJWT? {
        guard let data = doc.getSdjwtData() else {
            return nil
        }
        let sdJWTString = String(data: data, encoding: .utf8) ?? ""
        let signedSdjwt = try? CompactParser(serialisedString: sdJWTString).getSignedSdJwt()
        return signedSdjwt
    }
	
    public func getDocIdsToTypes() -> [PresentationSession.DocIDAndType] {
        return walletDocuments.map { m in
            if (m.id == ProxyPidDocument.proxyTagID) {
                return PresentationSession.DocIDAndType(docId: m.id, docTypes: ProxyPidDocument.proxyPidSupportedDocTypes, dataFormat: nil) //proxy pid supports SD-JWT and mdoc
            }
            return PresentationSession.DocIDAndType(docId: m.id, docTypes: m.docTypes, dataFormat: m.docFormat)
        }
	}
	
	/// Load documents from storage
	///
	/// Internally sets the ``docTypes``, ``mdocModels``, ``documentIds``, ``mdocModels``,  ``mdlModel``, ``pidModel`` variables
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]?  {
		do {
			guard let docs = try storageService.loadDocuments() else { return nil }
			await refreshWalletDocuments(docs)
			await refreshPublishedVars()
			return docs
		} catch {
			await setError(error)
			throw error
		}
	}
	
	func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: MdocDecodable {
		mdocModels.first(where: { type(of: $0) == of}) as? T
	}
	
	func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: MdocDecodable {
		mdocModels.filter({ type(of: $0) == of}).map { $0 as! T }
	}
	
    /// Get document model by index
    /// - Parameter index: Index in array of loaded models
    /// - Returns: The ``WalletDocument`` model
    public func getWalletDocument(index: Int) -> (any WalletDocument)? {
        guard index < walletDocuments.count else { return nil }
        return walletDocuments[index]
    }
	
    /// Get wallet document by id
    /// - Parameter id: The id of the document model to return
    /// - Returns: The ``WalletDocument`` model
    public func getWalletDocument(id: String) ->  (any WalletDocument)? {
        guard let i = documentIds.firstIndex(of: id)  else { return nil }
        return getWalletDocument(index: i)
    }

	/// Delete document by id
	/// - Parameter id: Document id
	public func deleteDocument(id: String) async throws {
		guard let i: Array<String?>.Index = documentIds.firstIndex(of: id)  else { return }
		do {
			try await deleteDocument(index: i)
		} catch {
			await setError(error)
			throw error
		}
	}
    
	/// Delete document by Index
	/// - Parameter index: Index in array of loaded wallet documents
	public func deleteDocument(index: Int) async throws {
		guard index < documentIds.count else { return }
		let id = walletDocuments[index].id
		do {
			try storageService.deleteDocument(id: id)
            
			await MainActor.run {
                if docTypes[index].contains(IsoMdlModel.isoDocType) { mdlModel = nil }
				if docTypes[index].contains(EuPidModel.euPidDocType) { pidModel = nil }
                walletDocuments.remove(at: index)
                
                if let mdocIndex = mdocModels.firstIndex(where: { $0.id == id}) {
                    mdocModels.remove(at: mdocIndex)
                }
			}
			await refreshPublishedVars()
		} catch {
			await setError(error)
			throw error
		}
	}
	
	/// Delete documenmts
	public func deleteDocuments() async throws {
		do {
			try storageService.deleteDocuments()
            await MainActor.run {
                walletDocuments = [];
                mdocModels = [];
                mdlModel = nil;
                pidModel = nil
            }
			await refreshPublishedVars()
		} catch {
			await setError(error)
			throw error
		}
	}
	
	@MainActor
	func setError(_ error: Error) {
		uiError = WalletError(description: error.localizedDescription, code: (error as NSError).code, userInfo: (error as NSError).userInfo)
	}
	
}



