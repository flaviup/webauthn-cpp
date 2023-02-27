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

        SessionDataType(const std::string& challenge,
            const std::optional<std::vector<uint8_t>>& userID,
            const std::string& userDisplayName,
            const int64_t expires,
            const Protocol::UserVerificationRequirementType userVerification,
            const std::optional<std::vector<std::vector<uint8_t>>>& allowedCredentialIDs = std::nullopt,
            const std::optional<Protocol::AuthenticationExtensionsType>& extensions = std::nullopt
        ) noexcept : 
            Challenge(challenge), 
            UserID(userID),
            UserDisplayName(userDisplayName),
            AllowedCredentialIDs(allowedCredentialIDs),
            Expires(expires),
            UserVerification(userVerification),
            Extensions(extensions) {
        }

        SessionDataType(const json& j) :
            Challenge(j["challenge"].get<std::string>()),
            UserDisplayName(j["user_display_name"].get<std::string>()),
            Expires(j["expires"].get<int64_t>()),
            UserVerification(j["userVerification"].get<Protocol::UserVerificationRequirementType>()) {

            if (j.find("user_id") != j.end()) {
                UserID.emplace(j["user_id"].get<std::vector<uint8_t>>());
            }

            if (j.find("allowed_credentials") != j.end()) {
                AllowedCredentialIDs.emplace(j["allowed_credentials"].get<std::vector<std::vector<uint8_t>>>());
            }

            if (j.find("extensions") != j.end()) {
                Extensions.emplace(j["extensions"].get<Protocol::AuthenticationExtensionsType>());
            }
        }

        SessionDataType(const SessionDataType& sessionData) noexcept = default;
        SessionDataType(SessionDataType&& sessionData) noexcept = default;
        ~SessionDataType() noexcept = default;

        SessionDataType& operator =(const SessionDataType& other) noexcept = default;
        SessionDataType& operator =(SessionDataType&& other) noexcept = default;

        std::string Challenge;
        std::optional<std::vector<uint8_t>> UserID;
        std::string UserDisplayName;
        std::optional<std::vector<std::vector<uint8_t>>> AllowedCredentialIDs;
        int64_t Expires;
        Protocol::UserVerificationRequirementType UserVerification;
        std::optional<Protocol::AuthenticationExtensionsType> Extensions;
    };

    inline void to_json(json& j, const SessionDataType& sessionData) {

        j = json{
            { "challenge",               sessionData.Challenge },
            { "user_display_name", sessionData.UserDisplayName }
        };

        if (sessionData.UserID) {
            j["user_id"] = sessionData.UserID.value();
        }

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
        j.at("user_display_name").get_to(sessionData.UserDisplayName);
        j.at("expires").get_to(sessionData.Expires);
        j.at("userVerification").get_to(sessionData.UserVerification);

        if (j.find("user_id") != j.end()) {
            sessionData.UserID.emplace(j["user_id"].get<std::vector<uint8_t>>());
        }

        if (j.find("allowed_credentials") != j.end()) {
            sessionData.AllowedCredentialIDs.emplace(j["allowed_credentials"].get<std::vector<std::vector<uint8_t>>>());
        }

        if (j.find("extensions") != j.end()) {
            sessionData.Extensions.emplace(j["extensions"].get<Protocol::AuthenticationExtensionsType>());
        }
    }
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_SESSION_DATA_IPP */