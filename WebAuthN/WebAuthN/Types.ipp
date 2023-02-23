//
//  Types.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_TYPES_IPP
#define WEBAUTHN_WEBAUTHN_TYPES_IPP

#include <fmt/format.h>
#include "Consts.ipp"
#include "Credential.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    using json = nlohmann::json;

    // TimeoutConfigType represents the WebAuthN timeouts configuration for either registration or login.
    struct TimeoutConfigType {

        TimeoutConfigType() noexcept = default;

        // Enforce the timeouts at the Relying Party / Server. This means if enabled and the user takes too long that even
        // if the browser does not enforce the timeout the Relying Party / Server will.
        bool Enforce;
        // Timeout is the timeout for logins/registrations when the UserVerificationRequirement is set to anything other
        // than discouraged.
        std::chrono::milliseconds Timeout;
        // TimeoutUVD is the timeout for logins/registrations when the UserVerificationRequirement is set to discouraged.
        std::chrono::milliseconds TimeoutUVD;
    };

    // TimeoutsConfig represents the WebAuthN timeouts configuration.
    struct TimeoutsConfigType  {

        TimeoutsConfigType() noexcept = default;

        TimeoutConfigType Login;
        TimeoutConfigType Registration;
    };

    // ConfigType represents the WebAuthN configuration.
    struct ConfigType {

        ConfigType() noexcept = default;

        // Validate that the config flags in Config are properly set
        inline std::optional<Protocol::ErrorType> Validate() const noexcept {

            if (Validated) {
                return std::nullopt;
            }

            if (RPDisplayName.empty()) {
                return Protocol::ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_EMPTY, "RPDisplayName"));
            }

            if (RPID.empty()) {
                return Protocol::ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_EMPTY, "RPID"));
            }

            if (!url.Parse(RPID)) {
                return Protocol::ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_NOT_VALID_URI, "RPID", RPID));
            }

            if (!RPIcon.empty()) {

                if (!url.Parse(RPIcon)) {
                    return Protocol::ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_NOT_VALID_URI, "RPIcon", RPIcon));
                }
            }

            auto defaultTimeoutConfig = DEFAULT_TIMEOUT;
            auto defaultTimeoutUVDConfig = DEFAULT_TIMEOUT_UVD;

            if (Timeouts.Login.Timeout.count() == 0LL) {
                Timeouts.Login.Timeout = defaultTimeoutConfig;
            }

            if (Timeouts.Login.TimeoutUVD.count() == 0LL) {
                Timeouts.Login.TimeoutUVD = defaultTimeoutUVDConfig;
            }

            if (Timeouts.Registration.Timeout.count() == 0LL) {
                Timeouts.Registration.Timeout = defaultTimeoutConfig;
            }

            if (Timeouts.Registration.TimeoutUVD.count() == 0LL) {
                Timeouts.Registration.TimeoutUVD = defaultTimeoutUVDConfig;
            }

            if (RPOrigins.empty()) {
                return Protocol::ErrorType().WithDetails("must provide at least one value to the 'RPOrigins' field");
            }

            if (!AuthenticatorSelection.RequireResidentKey.has_value()) {
                AuthenticatorSelection.RequireResidentKey = Protocol::ResidentKeyNotRequired();
            }

            if (!AuthenticatorSelection.UserVerification.has_value()) {
                AuthenticatorSelection.UserVerification = Protocol::UserVerificationRequirementType::Preferred;
            }

            Validated = true;

            return std::nullopt;
        }

        // RPID configures the Relying Party Server ID. This should generally be the origin without a scheme and port.
        std::string RPID;
        // RPDisplayName configures the display name for the Relying Party Server. This can be any string.
        std::string  RPDisplayName;
        // RPOrigins configures the list of Relying Party Server Origins that are permitted. These should be fully
        // qualified origins.
        std::vector<std::string > RPOrigins;
        // AttestationPreference sets the default attestation conveyance preferences.
        Protocol::ConveyancePreferenceType AttestationPreference;
        // AuthenticatorSelection sets the default authenticator selection options.
        mutable Protocol::AuthenticatorSelectionType AuthenticatorSelection;
        // Debug enables various debug options.
        bool Debug;
        // EncodeUserIDAsString ensures the user.id value during registrations is encoded as a raw UTF8 string. This is
        // useful when you only use printable ASCII characters for the random user.id but the browser library does not
        // decode the URL Safe Base64 data.
        bool EncodeUserIDAsString;
        // Timeouts configures various timeouts.
        mutable TimeoutsConfigType Timeouts;
        mutable bool Validated;
        // RPIcon sets the icon URL for the Relying Party Server.
        //
        // Deprecated: this option has been removed from newer specifications due to security considerations.
        std::string RPIcon;
    };

    // WebAuthNType is the primary interface of this package and contains the request handlers that should be called.
    struct WebAuthNType {

        WebAuthNType() noexcept = default;

        ConfigType Config;
    };

    // New creates a new WebAuthNType object given the proper ConfigType.
    inline Protocol::expected<WebAuthNType> New(const ConfigType& config) noexcept {

        auto result = config.Validate();

        if (result) {

            return Protocol::unexpected(fmt::format(ERR_FMT_CONFIG_VALIDATE, result.value()));
        }

        return WebAuthNType{.Config = config};
    }

    // IUser is am interface with the Relying Party's User entry and provides the fields and methods needed for WebAuthN
    // registration operations.
    struct IUser {

        IUser() noexcept = default;
        IUser(const IUser& user) noexcept = default;
        IUser(IUser&& user) noexcept = default;
        virtual ~IUser() noexcept = default;

        IUser& operator =(const IUser& other) noexcept = default;
        IUser& operator =(IUser&& other) noexcept = default;

        // GetWebAuthNID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
        // size of 64 bytes, and is not meant to be displayed to the user.
        //
        // To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
        // member, not the displayName nor name members. See Section 6.1 of [RFC8266].
        //
        // It's recommended this value is completely random and uses the entire 64 bytes.
        //
        // Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
        virtual std::vector<uint8_t> GetWebAuthNID() const = 0;

        // GetWebAuthNName provides the name attribute of the user account during registration and is a human-palatable name for the user
        // account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let the user
        // choose this, and SHOULD NOT restrict the choice more than necessary.
        //
        // Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
        virtual std::string GetWebAuthNName() const = 0;

        // GetWebAuthNDisplayName provides the name attribute of the user account during registration and is a human-palatable
        // name for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party
        // SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
        //
        // Specification: §5.4.3. User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname)
        virtual std::string GetWebAuthNDisplayName() const = 0;

        // GetWebAuthNCredentials provides the list of Credential objects owned by the user.
        virtual std::vector<CredentialType> GetWebAuthNCredentials() const = 0;

        // GetWebAuthNIcon is a deprecated option.
        // Deprecated: this has been removed from the specification recommendation. Suggest a blank string.
        virtual std::string GetWebAuthNIcon() const = 0;
    };

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

#endif /* WEBAUTHN_WEBAUTHN_TYPES_IPP */