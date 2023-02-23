//
//  SessionData.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_SESSION_DATA_IPP
#define WEBAUTHN_WEBAUTHN_SESSION_DATA_IPP

#include "Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    using json = nlohmann::json;

    // SessionDataType is the data that should be stored by the Relying Party for the duration of the web authentication
    // ceremony.
    struct SessionDataType {

        SessionDataType() noexcept = default;
        SessionDataType(const json& j) :
            Challenge(j["challenge"].get<std::string>()),
            UserID(j["user_id"].get<std::vector<uint8_t>>()),
            UserDisplayName(j["user_display_name"].get<std::string>()),
            Expires(j["expires"].get<uint64_t>()),
            UserVerification(j["userVerification"].get<Protocol::UserVerificationRequirementType>()) {

            if (j.find("allowed_credentials") != j.end()) {
                AllowedCredentialIDs.emplace(j["allowed_credentials"].get<std::vector<std::vector<uint8_t>>>();
            }

            if (j.find("extensions") != j.end()) {
                Extensions.emplace(j["extensions"].get<Protocol::AuthenticationExtensionsType>();
            }
        }

        std::string Challenge;
        std::vector<uint8_t> UserID;
        std::string UserDisplayName;
        std::optional<std::vector<std::vector<uint8_t>>> AllowedCredentialIDs;
        uint64_t Expires;
        Protocol::UserVerificationRequirementType UserVerification;
        std::optional<Protocol::AuthenticationExtensionsType> Extensions;
    };

    inline void to_json(json& j, const SessionDataType& sessionData) {

        j = json{
            { "challenge",               sessionData.Challenge },
            { "user_id",                    sessionData.UserID },
            { "user_display_name", sessionData.UserDisplayName }
        };

        if (sessionData.AllowedCredentialIDs) {
            j["allowed_credentials"] = sessionData.AllowedCredentialIDs.value();
        }

        j["expires"] = sessionData.Expires;
        j["userVerification"] = sessionData.UserVerification;

        if (sessionData.Extensions) {
            j["extensions"] = sessionData.Extensions.value();
        }
    }

    inline void from_json(const json& j, SessionDataType& sessionData) {

        j.at("challenge").get_to(sessionData.Challenge);
        j.at("user_id").get_to(sessionData.UserID);
        j.at("user_display_name").get_to(sessionData.UserDisplayName);
        j.at("expires").get_to(sessionData.Expires);
        j.at("userVerification").get_to(sessionData.UserVerification);

        if (j.find("allowed_credentials") != j.end()) {
            sessionData.AllowedCredentialIDs.emplace(j["allowed_credentials"].get<std::vector<std::vector<uint8_t>>>();
        }

        if (j.find("extensions") != j.end()) {
            sessionData.Extensions.emplace(j["extensions"].get<Protocol::AuthenticationExtensionsType>();
        }
    }
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_SESSION_DATA_IPP */