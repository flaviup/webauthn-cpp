//
//  Entities.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/17/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_ENTITIES_IPP
#define WEBAUTHN_PROTOCOL_ENTITIES_IPP

#include <optional>
#include <nlohmann/json.hpp>
#include "Base64.ipp"
#include "Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol {

    using json = nlohmann::json;

    // CredentialEntityType represents the PublicKeyCredentialEntityType IDL and it describes a user account, or a WebAuthn Relying
    // Party with which a public key credential is associated.
    //
    // Specification: §5.4.1. Public Key Entity Description (https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity)
    struct CredentialEntityType {

        CredentialEntityType() noexcept = default;

        CredentialEntityType(const std::string& name, const std::optional<std::string>& icon = std::nullopt) noexcept : 
            Name(name), 
            Icon(icon) {
        }

        CredentialEntityType(const json& j) :
            Name(j["name"].get<std::string>()) {

            if (j.find("icon") != j.end()) {
                Icon.emplace(j["icon"].get<std::string>());
            }
        }

        CredentialEntityType(const CredentialEntityType& credentialEntity) noexcept = default;
        CredentialEntityType(CredentialEntityType&& credentialEntity) noexcept = default;
        virtual ~CredentialEntityType() noexcept = default;

        CredentialEntityType& operator =(const CredentialEntityType& other) noexcept = default;
        CredentialEntityType& operator =(CredentialEntityType&& other) noexcept = default;

        // A human-palatable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents:
        //
        // When inherited by PublicKeyCredentialRpEntity it is a human-palatable identifier for the Relying Party,
        // intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
        //
        // When inherited by PublicKeyCredentialUserEntity, it is a human-palatable identifier for a user account. It is
        // intended only for display, i.e., aiding the user in determining the difference between user accounts with similar
        // displayNames. For example, "alexm", "alex.p.mueller@example.com" or "+14255551234".
        std::string Name;

        // A serialized URL which resolves to an image associated with the entity. For example,
        // this could be a user’s avatar or a Relying Party's logo. This URL MUST be an a priori
        // authenticated URL. Authenticators MUST accept and store a 128-byte minimum length for
        // an icon member’s value. Authenticators MAY ignore an icon member’s value if its length
        // is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL,
        // at the cost of needing more storage.
        //
        // Deprecated: this has been removed from the specification recommendations.
        std::optional<std::string> Icon;
    };

    inline void to_json(json& j, const CredentialEntityType& credentialEntity) {

        j = json{
            { "name", credentialEntity.Name }
        };

        if (credentialEntity.Icon) {
            j["icon"] = credentialEntity.Icon.value();
        }
    }

    inline void from_json(const json& j, CredentialEntityType& credentialEntity) {

        j.at("name").get_to(credentialEntity.Name);

        if (j.find("icon") != j.end()) {
            credentialEntity.Icon.emplace(j["icon"].get<std::string>());
        }
    }

    // The RelyingPartyEntityType represents the PublicKeyCredentialRpEntityType IDL and is used to supply additional Relying Party
    // attributes when creating a new credential.
    //
    // Specification: §5.4.2. Relying Party Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dictionary-rp-credential-params)
    struct RelyingPartyEntityType : public CredentialEntityType {

        RelyingPartyEntityType() noexcept = default;

        RelyingPartyEntityType(const std::string& id, 
            const std::string& name,
            const std::optional<std::string>& icon = std::nullopt) noexcept : 
            CredentialEntityType(name, icon),
            ID(id) {
        }

        RelyingPartyEntityType(const json& j) :
            CredentialEntityType(j),
            ID(j["id"].get<std::string>()) {
        }

        RelyingPartyEntityType(const RelyingPartyEntityType& relyingPartyEntity) noexcept = default;
        RelyingPartyEntityType(RelyingPartyEntityType&& relyingPartyEntity) noexcept = default;
        ~RelyingPartyEntityType() noexcept override = default;

        RelyingPartyEntityType& operator =(const RelyingPartyEntityType& other) noexcept = default;
        RelyingPartyEntityType& operator =(RelyingPartyEntityType&& other) noexcept = default;

        // A unique identifier for the Relying Party entity, which sets the RP ID.
        std::string ID;
    };

    inline void to_json(json& j, const RelyingPartyEntityType& relyingPartyEntity) {

        json _j;
        to_json(_j, static_cast<const CredentialEntityType&>(relyingPartyEntity));
        _j["id"] = relyingPartyEntity.ID;
        j = _j;
    }

    inline void from_json(const json& j, RelyingPartyEntityType& relyingPartyEntity) {

        from_json(j, static_cast<CredentialEntityType&>(relyingPartyEntity));
        j.at("id").get_to(relyingPartyEntity.ID);
    }

    // The UserEntityType represents the PublicKeyCredentialUserEntityType IDL and is used to supply additional user account
    // attributes when creating a new credential.
    //
    // Specification: §5.4.3 User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialuserentity)
    struct UserEntityType : public CredentialEntityType {

        UserEntityType() noexcept = default;

        UserEntityType(const URLEncodedBase64Type& id, 
            const std::string& name, 
            const std::optional<std::string>& displayName = std::nullopt, 
            const std::optional<std::string>& icon = std::nullopt) noexcept : 
            CredentialEntityType(name, icon),
            ID(id), 
            DisplayName(displayName) {
        }

        UserEntityType(const json& j) :
            CredentialEntityType(j),
            ID(j["id"].get<URLEncodedBase64Type>()) {

            if (j.find("displayName") != j.end()) {
                DisplayName.emplace(j["displayName"].get<std::string>());
            }
        }

        UserEntityType(const UserEntityType& userEntity) noexcept = default;
        UserEntityType(UserEntityType&& userEntity) noexcept = default;
        ~UserEntityType() noexcept override = default;

        UserEntityType& operator =(const UserEntityType& other) noexcept = default;
        UserEntityType& operator =(UserEntityType&& other) noexcept = default;

        // ID is the user handle of the user account entity. To ensure secure operation,
        // authentication and authorization decisions MUST be made on the basis of this id
        // member, not the displayName nor name members. See Section 6.1 of
        // [RFC8266](https://www.w3.org/TR/webauthn/#biblio-rfc8266).
        URLEncodedBase64Type ID;

        // A human-palatable name for the user account, intended only for display.
        // For example, "Alex P. Müller" or "田中 倫". The Relying Party SHOULD let
        // the user choose this, and SHOULD NOT restrict the choice more than necessary.
        std::optional<std::string> DisplayName;
    };

    inline void to_json(json& j, const UserEntityType& userEntity) {

        json _j;
        to_json(_j, static_cast<const CredentialEntityType&>(userEntity));
        _j["id"] = userEntity.ID;

        if (userEntity.DisplayName) {
            _j["icon"] = userEntity.DisplayName.value();
        }
        j = _j;
    }

    inline void from_json(const json& j, UserEntityType& userEntity) {

        from_json(j, static_cast<CredentialEntityType&>(userEntity));
        j.at("id").get_to(userEntity.ID);

        if (j.find("displayName") != j.end()) {
            userEntity.DisplayName.emplace(j["displayName"].get<std::string>());
        }
    }
} // namespace WebAuthN::Protocol

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_ENTITIES_IPP */
