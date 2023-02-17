//
//  Credential.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_CREDENTIAL_IPP
#define WEBAUTHN_PROTOCOL_CREDENTIAL_IPP

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "Base64.ipp"
#include "Extensions.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    struct Credential {

        Credential() noexcept = default;
        Credential(const json& j) :
            ID(j["id"].get<std::string>()),
            Type(j["type"].get<std::string>()) {
        }

        std::string ID;
        std::string Type;
    };

    struct ParsedCredential {

        ParsedCredential() noexcept = default;
        ParsedCredential(const json& j) :
            ID(j["id"].get<std::string>()),
            Type(j["type"].get<std::string>()) {
        }
        ParsedCredential(const std::vector<std::uint8_t>& cbor) :
            ParsedCredential(json::from_cbor(cbor)) {
        }

        std::string ID;
        std::string Type;
    };

    struct PublicKeyCredential : public Credential {

        PublicKeyCredential() noexcept = default;
        PublicKeyCredential(const json& j) :
            Credential(j),
            RawID(j["rawId"].get<URLEncodedBase64>()) {
            
            if (j.find("clientExtensionResults") != j.end()) {
                ClientExtensionResults = j["clientExtensionResults"].get<AuthenticationExtensionsClientOutputs>();
            }

            if (j.find("authenticatorAttachment") != j.end()) {
                AuthenticatorAttachment = j["authenticatorAttachment"].get<std::string>();
            }
        }

        URLEncodedBase64 RawID;
        AuthenticationExtensionsClientOutputs ClientExtensionResults;
        std::string AuthenticatorAttachment;
    };

    struct ParsedPublicKeyCredential : public ParsedCredential {

        ParsedPublicKeyCredential() noexcept = default;
        ParsedPublicKeyCredential(const json& j) :
            ParsedCredential(j),
            RawID(j["rawId"].get<URLEncodedBase64>()) {
            
            if (j.find("clientExtensionResults") != j.end()) {
                ClientExtensionResults = j["clientExtensionResults"].get<AuthenticationExtensionsClientOutputs>();
            }

            if (j.find("authenticatorAttachment") != j.end()) {
                AuthenticatorAttachment = j["authenticatorAttachment"].get<std::string>();
            }
        }

        ParsedPublicKeyCredential(const std::vector<std::uint8_t>& cbor) :
            ParsedPublicKeyCredential(json::from_cbor(cbor)) {
        }

        URLEncodedBase64 RawID;
        AuthenticationExtensionsClientOutputs ClientExtensionResults;
        std::string AuthenticatorAttachment;
    };

    struct CredentialCreationResponse : PublicKeyCredential {

        CredentialCreationResponse() noexcept = default;
        CredentialCreationResponse(const json& j) :
            PublicKeyCredential(j),
            AttestationResponse(j["response"].get<AuthenticatorAttestationResponse>()) {
            
            if (j.find("transports") != j.end()) {
                Transports = j["transports"].get<std::vector<std::string>>();
            }
        }

        AuthenticatorAttestationResponse AttestationResponse;
        std::vector<std::string> Transports;
    };

    struct ParsedCredentialCreationData : ParsedPublicKeyCredential {

        ParsedCredentialCreationData() noexcept = default;
        ParsedCredentialCreationData(const json& j) :
            ParsedPublicKeyCredential(j) {
            
            if (j.find("response") != j.end()) {
                Response = j["response"].get<ParsedAttestationResponse>();
            }

            if (j.find("raw") != j.end()) {
                Raw = CredentialCreationResponse(j["raw"]);
            }
        }

        ParsedAttestationResponse Response;
        CredentialCreationResponse Raw;
    };
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_CREDENTIAL_IPP */
