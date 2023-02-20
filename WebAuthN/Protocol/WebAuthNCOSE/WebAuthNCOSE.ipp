//
//  WebAuthNCOSE.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP
#define WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol::WebAuthNCOSE {

    using json = nlohmann::json;

    // COSEAlgorithmIdentifierType is a number identifying a cryptographic algorithm. The algorithm identifiers SHOULD be values
    // registered in the IANA COSE Algorithms registry [https://www.w3.org/TR/webauthn/#biblio-iana-cose-algs-reg], for
    // instance, -7 for "ES256" and -257 for "RS256".
    //
    // Specification: §5.8.5. Cryptographic Algorithm Identifier (https://www.w3.org/TR/webauthn/#sctn-alg-identifier)
    enum class COSEAlgorithmIdentifierType : int {

        // AlgES256 ECDSA with SHA-256.
        AlgES256 = -7,

        // AlgES384 ECDSA with SHA-384.
        AlgES384 = -35,

        // AlgES512 ECDSA with SHA-512.
        AlgES512 = -36,

        // AlgRS1 RSASSA-PKCS1-v1_5 with SHA-1.
        AlgRS1 = -65535,

        // AlgRS256 RSASSA-PKCS1-v1_5 with SHA-256.
        AlgRS256 = -257,

        // AlgRS384 RSASSA-PKCS1-v1_5 with SHA-384.
        AlgRS384 = -258,

        // AlgRS512 RSASSA-PKCS1-v1_5 with SHA-512.
        AlgRS512 = -259,

        // AlgPS256 RSASSA-PSS with SHA-256.
        AlgPS256 = -37,

        // AlgPS384 RSASSA-PSS with SHA-384.
        AlgPS384 = -38,

        // AlgPS512 RSASSA-PSS with SHA-512.
        AlgPS512 = -39,

        // AlgEdDSA EdDSA.
        AlgEdDSA = -8,

        // AlgES256K is ECDSA using secp256k1 curve and SHA-256.
        AlgES256K = -47
    };

    inline void from_json(const json& j, COSEAlgorithmIdentifierType& coseAlgorithmIdentifier) {

        auto value = j.get<int>();
        coseAlgorithmIdentifier = static_cast<COSEAlgorithmIdentifierType>(value);
    }

    inline void to_json(json& j, const COSEAlgorithmIdentifierType& coseAlgorithmIdentifier) {

        j = json{
            static_cast<int>(coseAlgorithmIdentifier)
        };
    }

} // namespace WebAuthN::Protocol::WebAuthNCOSE

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_WEBAUTHNCOSE_IPP */