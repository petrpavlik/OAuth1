//
//  OAuth1.swift
//
//  Created by Collin Hundley on 8/12/16.
//

import Foundation
import Cryptor

fileprivate extension String {
    func stringByAddingPercentEncodingForRFC3986() -> String? {
        //let unreserved = "-._~/?"
        //let unreserved = "-._~?"
        let unreserved = "-._~?"
        let allowed = NSMutableCharacterSet.alphanumeric()
        allowed.addCharacters(in: unreserved)
        return self.addingPercentEncoding(withAllowedCharacters: allowed as CharacterSet)
    }
}

public struct OAuth1 {

    public enum Method: String {
        case get = "GET"
        case post = "POST"
    }
    
    let consumerKey: String
    let consumerSecret: String
    let token: String
    let tokenSecret: String
    private let nonceChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    public init(consumerKey: String, consumerSecret: String, token: String, tokenSecret: String) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.token = token
        self.tokenSecret = tokenSecret
    }
    
    public func generateHeaders(url: String, params queryParams: [String:String], method: Method) -> String {
        // 1
        let nonce = generateNonce()
        let timestamp = "\(Int64(Date().timeIntervalSince1970.rounded()))"
        
        var params:[String:String] = [
            "oauth_consumer_key": consumerKey,
            "oauth_nonce": nonce,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": timestamp,
            "oauth_token": token,
            "oauth_version": "1.0"
        ]
        
        queryParams.forEach { (param) in
            params[param.key] = percentEncode(param.value)
        }
        
        let sortedParams = params.sorted(by: <)
        
        let paramString = (sortedParams.flatMap({ (key, value) -> String in
            return "\(key)=\(value)"
        }) as Array).joined(separator: "&")
        
        
        
        // 3
        let signatureBase = "\(method.rawValue)&\(percentEncode(url))&\(percentEncode(paramString))"
        
        // 4
        let key = CryptoUtils.byteArray(from: "\(percentEncode(consumerSecret))&\(percentEncode(tokenSecret))")
        let data = CryptoUtils.byteArray(from: signatureBase)
        let hmac = HMAC(using: HMAC.Algorithm.sha1, key: key).update(byteArray: data)!.final()
        
        let signature:String = Data(hmac).base64EncodedString()

        let oauthHeader = "OAuth oauth_consumer_key=\"\(params["oauth_consumer_key"]!)\", oauth_nonce=\"\(params["oauth_nonce"]!)\", oauth_signature=\"\(percentEncode(signature))\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"\(params["oauth_timestamp"]!)\", oauth_token=\"\(params["oauth_token"]!)\", oauth_version=\"1.0\""
        
        return oauthHeader
    }
    
    
    /// Generates a random 32-character alphanumeric nonce.
    ///
    /// - returns: the nonce.
    private func generateNonce() -> String {
        var nonce = ""
        for _ in 0..<32 {
            let rand = Int(arc4random_uniform(62))
            nonce += String(nonceChars[nonceChars.index(nonceChars.startIndex, offsetBy: rand)])
        }
        return nonce
    }
    
    private func percentEncode(_ str: String) -> String {
        return str.stringByAddingPercentEncodingForRFC3986()!
    }
    

}
