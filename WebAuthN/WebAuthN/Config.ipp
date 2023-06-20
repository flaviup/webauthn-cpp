//
//  Config.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/23/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_WEBAUTHN_CONFIG_IPP
#define WEBAUTHN_WEBAUTHN_CONFIG_IPP

#include <fmt/format.h>
#include "Consts.ipp"
#include "../Protocol/Options.ipp"
#include "../Util/UrlParse.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::WebAuthN {

    using json = nlohmann::json;

    // TimeoutConfigType represents the WebAuthN timeouts configuration for either registration or login.
    struct TimeoutConfigType {
        
        using Duration = std::chrono::milliseconds;
        using DurationIntegerType = Duration::rep;

        TimeoutConfigType() noexcept = default;

        TimeoutConfigType(const json& j) :
            Enforce(j["enforce"].get<bool>()),
            Timeout(Duration{j["timeout"].get<TimeoutConfigType::DurationIntegerType>()}),
            TimeoutUVD(Duration{j["timeoutUVD"].get<TimeoutConfigType::DurationIntegerType>()}) {
        }

        // Enforce the timeouts at the Relying Party / Server. This means if enabled and the user takes too long that even
        // if the browser does not enforce the timeout the Relying Party / Server will.
        bool Enforce{false};
        // Timeout is the timeout for logins/registrations when the UserVerificationRequirement is set to anything other
        // than discouraged.
        Duration Timeout;
        // TimeoutUVD is the timeout for logins/registrations when the UserVerificationRequirement is set to discouraged.
        Duration TimeoutUVD;
    };

    inline void to_json(json& j, const TimeoutConfigType& timeoutConfig) {

        j = json{
            { "enforce",               timeoutConfig.Enforce },
            { "timeout",       timeoutConfig.Timeout.count() },
            { "timeoutUVD", timeoutConfig.TimeoutUVD.count() }
        };
    }

    inline void from_json(const json& j, TimeoutConfigType& timeoutConfig) {

        j.at("enforce").get_to(timeoutConfig.Enforce);
        timeoutConfig.Timeout = TimeoutConfigType::Duration{j["timeout"].get<TimeoutConfigType::DurationIntegerType>()};
        timeoutConfig.TimeoutUVD = TimeoutConfigType::Duration{j["timeoutUVD"].get<TimeoutConfigType::DurationIntegerType>()};
    }

    // TimeoutsConfig represents the WebAuthN timeouts configuration.
    struct TimeoutsConfigType  {

        TimeoutsConfigType() noexcept = default;

        TimeoutsConfigType(const json& j) :
            Login(j["login"].get<TimeoutConfigType>()),
            Registration(j["registration"].get<TimeoutConfigType>()) {
        }

        TimeoutConfigType Login;
        TimeoutConfigType Registration;
    };

    inline void to_json(json& j, const TimeoutsConfigType& timeoutsConfig) {

        j = json{
            { "login",               timeoutsConfig.Login },
            { "registration", timeoutsConfig.Registration }
        };
    }

    inline void from_json(const json& j, TimeoutsConfigType& timeoutsConfig) {

        j.at("login").get_to(timeoutsConfig.Login);
        j.at("registration").get_to(timeoutsConfig.Registration);
    }

    // ConfigType represents the WebAuthN configuration.
    struct ConfigType {

        ConfigType() noexcept = default;
        
        ConfigType(const std::string& rpID,
                   const std::string& rpDisplayName,
                   const std::vector<std::string>& rpOrigins,
                   Protocol::ConveyancePreferenceType attestationPreference = Protocol::ConveyancePreferenceType::IndirectAttestation,
                   const Protocol::AuthenticatorSelectionType& authenticatorSelection = Protocol::AuthenticatorSelectionType{},
                   bool debug = false,
                   bool encodeUserIDAsString = false,
                   const TimeoutsConfigType& timeouts = TimeoutsConfigType{}) noexcept :
            RPID(rpID),
            RPDisplayName(rpDisplayName),
            RPOrigins(rpOrigins),
            AttestationPreference(attestationPreference),
            AuthenticatorSelection(authenticatorSelection),
            Debug(debug),
            EncodeUserIDAsString(encodeUserIDAsString),
            Timeouts(timeouts) {
        }

        ConfigType(const json& j) :
            RPID(j["rpID"].get<std::string>()),
            RPDisplayName(j["rpDisplayName"].get<std::string>()),
            RPOrigins(j["rpOrigins"].get<std::vector<std::string>>()),
            AttestationPreference(j["attestationPreference"].get<Protocol::ConveyancePreferenceType>()),
            AuthenticatorSelection(j["authenticatorSelection"].get<Protocol::AuthenticatorSelectionType>()),
            Debug(j["debug"].get<bool>()),
            EncodeUserIDAsString(j["encodeUserIDAsString"].get<bool>()),
            Timeouts(j["timeouts"].get<TimeoutsConfigType>()),
            RPIcon(j["rpIcon"].get<std::string>()) {
        }

        // Validate that the config flags in Config are properly set
        inline std::optional<ErrorType> Validate() const noexcept {

            if (Validated) {
                return std::nullopt;
            }

            if (RPDisplayName.empty()) {
                return ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_EMPTY, "RPDisplayName"));
            }

            if (RPID.empty()) {
                return ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_EMPTY, "RPID"));
            }

            if (!Util::Url::Parse(RPID)) {
                return ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_NOT_VALID_URI, "RPID", RPID));
            }

            if (!RPIcon.empty()) {

                if (!Util::Url::Parse(RPIcon)) {
                    return ErrorType().WithDetails(fmt::format(ERR_FMT_FIELD_NOT_VALID_URI, "RPIcon", RPIcon));
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
                return ErrorType().WithDetails("must provide at least one value to the 'RPOrigins' field");
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

        static inline ConfigType Load(const std::string& configFilePath) noexcept {

            std::ifstream cfgFileStream(configFilePath);
            json j;
            cfgFileStream >> j;

            return ConfigType{j};
        }

        // RPID configures the Relying Party Server ID. This should generally be the origin without a scheme and port.
        std::string RPID;
        // RPDisplayName configures the display name for the Relying Party Server. This can be any string.
        std::string RPDisplayName;
        // RPOrigins configures the list of Relying Party Server Origins that are permitted. These should be fully
        // qualified origins.
        std::vector<std::string> RPOrigins;
        // AttestationPreference sets the default attestation conveyance preferences.
        Protocol::ConveyancePreferenceType AttestationPreference;
        // AuthenticatorSelection sets the default authenticator selection options.
        mutable Protocol::AuthenticatorSelectionType AuthenticatorSelection;
        // Debug enables various debug options.
        bool Debug{false};
        // EncodeUserIDAsString ensures the user.id value during registrations is encoded as a raw UTF8 string. This is
        // useful when you only use printable ASCII characters for the random user.id but the browser library does not
        // decode the URL Safe Base64 data.
        bool EncodeUserIDAsString{false};
        // Timeouts configures various timeouts.
        mutable TimeoutsConfigType Timeouts;
        mutable bool Validated{false};
        // RPIcon sets the icon URL for the Relying Party Server.
        //
        // Deprecated: this option has been removed from newer specifications due to security considerations.
        std::string RPIcon;
    };

    inline void to_json(json& j, const ConfigType& config) {

        j = json{
            { "rpID",                                     config.RPID },
            { "rpDisplayName",                   config.RPDisplayName },
            { "rpOrigins",                           config.RPOrigins },
            { "attestationPreference",   config.AttestationPreference },
            { "authenticatorSelection", config.AuthenticatorSelection },
            { "debug",                                   config.Debug },
            { "encodeUserIDAsString",     config.EncodeUserIDAsString },
            { "timeouts",                             config.Timeouts },
            { "rpIcon",                                 config.RPIcon }
        };
    }

    inline void from_json(const json& j, ConfigType& config) {

        j.at("rpID").get_to(config.RPID);
        j.at("rpDisplayName").get_to(config.RPDisplayName);
        j.at("rpOrigins").get_to(config.RPOrigins);
        j.at("attestationPreference").get_to(config.AttestationPreference);
        j.at("authenticatorSelection").get_to(config.AuthenticatorSelection);
        j.at("debug").get_to(config.Debug);
        j.at("encodeUserIDAsString").get_to(config.EncodeUserIDAsString);
        j.at("timeouts").get_to(config.Timeouts);
        j.at("rpIcon").get_to(config.RPIcon);
    }
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_CONFIG_IPP */
