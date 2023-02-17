//
//  Entities.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ENTITIES_IPP
#define WEBAUTHN_PROTOCOL_ENTITIES_IPP

#include <string>
#include <nlohmann/json.hpp>
#include "Base64.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    struct CredentialEntity {

        CredentialEntity() noexcept = default;
        CredentialEntity(const json& j) :
            Name(j["name"].get<std::string>()) {

            if (j.find("icon") != j.end()) {
                Icon = j["icon"].get<std::string>();
            }
        }

        std::string Name;
        std::string Icon;
    };

    struct RelyingPartyEntity : public CredentialEntity {

        RelyingPartyEntity() noexcept = default;
        RelyingPartyEntity(const json& j) :
            CredentialEntity(j),
            ID(j["id"].get<std::string>()) {
        }

        std::string ID;
    };

    struct UserEntity : public CredentialEntity {

        UserEntity() noexcept = default;
        UserEntity(const json& j) :
            CredentialEntity(j),
            ID(j["id"].get<URLEncodedBase64>()) {

            if (j.find("displayName") != j.end()) {
                DisplayName = j["displayName"].get<std::string>();
            }
        }

        std::string DisplayName;
        URLEncodedBase64 ID;
    };
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ENTITIES_IPP */
