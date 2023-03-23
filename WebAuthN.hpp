//
//  WebAuthN.hpp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_HPP
#define WEBAUTHN_HPP

#include "Version.ipp"
#include "WebAuthN/WebAuthN/WebAuthN.ipp"
#include "WebAuthN/Protocol/AttestationAndroidKey.ipp"
#include "WebAuthN/Protocol/AttestationApple.ipp"
#include "WebAuthN/Protocol/AttestationPacked.ipp"
#include "WebAuthN/Protocol/AttestationSafetyNet.ipp"
#include "WebAuthN/Protocol/AttestationPlayIntegrity.ipp"
#include "WebAuthN/Protocol/AttestationU2F.ipp"
#include "WebAuthN/Protocol/AttestationTPM.ipp"

inline WebAuthN::expected<WebAuthN::WebAuthN::WebAuthNType>
GetWebAuthN(const WebAuthN::WebAuthN::ConfigType& config, bool registerAllAttestations = true) noexcept {

    if (registerAllAttestations) {

        WebAuthN::Protocol::RegisterAndroidKeyAttestation();
        WebAuthN::Protocol::RegisterAppleAttestation();
        WebAuthN::Protocol::RegisterPackedAttestation();
        WebAuthN::Protocol::RegisterSafetyNetAttestation();
        WebAuthN::Protocol::RegisterPlayIntegrityAttestation();
        WebAuthN::Protocol::RegisterU2FAttestation();
        WebAuthN::Protocol::RegisterTPMAttestation();
    }

    return WebAuthN::WebAuthN::WebAuthNType::New(config);
}

#endif /* WEBAUTHN_HPP */
