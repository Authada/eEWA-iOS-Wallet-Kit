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

/// View model used in SwiftUI for presentation request elements
public struct DocElementsViewModel: Identifiable {
	public var id: String { docId }
	public var docId: String
	public let docType: String
    public let dataFormat: DataFormat?
	public var isEnabled: Bool
	public var elements: [ElementViewModel]
}
extension DocElementsViewModel {
	static func fluttenItemViewModels(_ nsItems: [String:[String]], valid isEnabled: Bool, mandatoryElementKeys: [String]) -> [ElementViewModel] {
		nsItems.map { k,v in nsItemsToViewModels(k,v, isEnabled, mandatoryElementKeys) }.flatMap {$0}
	}
	
	static func nsItemsToViewModels(_ ns: String, _ items: [String], _ isEnabled: Bool, _ mandatoryElementKeys: [String]) -> [ElementViewModel] {
		items.map { ElementViewModel(nameSpace: ns, elementIdentifier:$0, isMandatory: mandatoryElementKeys.contains($0), isEnabled: isEnabled) }
	}
	
	static func getMandatoryElementKeys(docType: String) -> [String] {
		switch docType {
		case IsoMdlModel.isoDocType:
			return IsoMdlModel.isoMandatoryElementKeys
		case EuPidModel.euPidDocType:
			return EuPidModel.pidMandatoryElementKeys
		default:
			return []
		}
	}
}

extension RequestedDocumentFormatItems {
    func toDocElementViewModels(docId: String, docTypes: [String], dataFormat:DataFormat?, valid: Bool) -> [DocElementsViewModel] {
        
        var finalViewModels :[DocElementsViewModel] = []
        
        
        for (identifierKey, formatDict) in self {
            var matchingDetails :[DataFormat:RequestedDocumentDetails] = [:]
            if let dataFormat {
                if let formatDetails = formatDict[dataFormat] {
                    matchingDetails[dataFormat] = formatDetails
                }
            }
            else {
                matchingDetails = formatDict
            }
            
            for dFormat in matchingDetails.keys {
                if let details = matchingDetails[dFormat] {
                    for docType in docTypes {
                        if details.allowedDocTypes.contains(docType) {
                            var nsItems = details.fields
                            if var fieldNames = nsItems[identifierKey],
                               fieldNames.contains("vct"),
                               (dataFormat == nil || dataFormat == .sdjwt) {
                                fieldNames.removeAll(where: { $0 == "vct" })
                                nsItems[identifierKey] = fieldNames
                            }
                            let viewM = DocElementsViewModel(docId: docId, docType: docType, dataFormat: dFormat, isEnabled: valid, elements: DocElementsViewModel.fluttenItemViewModels(nsItems, valid: valid, mandatoryElementKeys: DocElementsViewModel.getMandatoryElementKeys(docType: docType)))
                            finalViewModels.append(viewM)
                            break //only one docType is needed
                        }
                    }
                }
            }
        }

        return finalViewModels
    }
}

extension Array where Element == DocElementsViewModel {
	public var items: RequestItems { Dictionary(grouping: self, by: \.docId).mapValues { $0.first!.elements.filter(\.isSelected).nsDictionary } }

	func merging(with other: Self) -> Self {
		var res = Self()
		for otherDE in other {
			if let exist = first(where: { $0.docId == otherDE.docId})	{
				let newElements = (exist.elements + otherDE.elements).sorted(by: { $0.isEnabled && $1.isDisabled })
                res.append(DocElementsViewModel(docId: exist.docId, docType: exist.docType, dataFormat: exist.dataFormat, isEnabled: exist.isEnabled, elements: newElements))
			}
			else { res.append(otherDE) }
		}
		return res
	}
}

public struct ElementViewModel: Identifiable {
	public var id: String { "\(nameSpace)_\(elementIdentifier)" }
	public let nameSpace: String
	public let elementIdentifier: String
	public let isMandatory: Bool
	public var isEnabled: Bool
	public var isDisabled: Bool { !isEnabled }
	public var isSelected = true
}

extension Array where Element == ElementViewModel {
	var nsDictionary: [String: [String]] { Dictionary(grouping: self, by: \.nameSpace).mapValues { $0.map(\.elementIdentifier)} }
}
