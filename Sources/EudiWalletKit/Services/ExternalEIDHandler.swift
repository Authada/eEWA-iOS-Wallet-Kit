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
//  ExternalEIDHandler.swift
//  


import Foundation

public protocol ExternalURLService {
    func openExtern(url: URL) -> Bool
}

class ExternalEIDHandler: NSObject {
    
    let authorizationCodeURL:URL
    var localContinuation: CheckedContinuation<String?, Error>?

    
    init(authorizationCodeURL: URL) {

        self.authorizationCodeURL = authorizationCodeURL
    }
    
    func startEiDAndGetAuthCode() async throws -> String? {
        NotificationCenter.default.addObserver(self, selector: #selector(self.authenticationTokenReceived(notification:)), name: NSNotification.Name("AuthenticationCode"), object: nil)
        return try await withCheckedThrowingContinuation { c in
            localContinuation = c
            if let extrenalURLHandler = EudiWallet.standard.externalURLService {
                DispatchQueue.main.async {
                    _ = extrenalURLHandler.openExtern(url: self.authorizationCodeURL)
                }
            }
        }
    }
    
    @objc func authenticationTokenReceived(notification:NSNotification) {
        
        if let localContinuation {
            if let authenticationTokenURL = notification.userInfo?["authenticationToken"] as? String {
                guard let url = URLComponents(string: authenticationTokenURL) else { return  }
                let authtoken = url.queryItems?.first(where: { $0.name == "code" })?.value
                localContinuation.resume(returning: authtoken)
            } else {
                localContinuation.resume(throwing:OpenId4VCIError.authorizeResponseNoCode)
            }
        }
        cleanup()
    }
    
    private func cleanup() {
        localContinuation = nil
        NotificationCenter.default.removeObserver(self, name: Notification.Name("AuthenticationCode"), object: nil)
    }
}
