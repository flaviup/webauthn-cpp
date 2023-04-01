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

    // TimeoutConfigType represents the WebAuthN timeouts configuration for either registration or login.
    struct TimeoutConfigType {

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

        TimeoutConfigType Login;
        TimeoutConfigType Registration;
    };

    // ConfigType represents the WebAuthN configuration.
    struct ConfigType {

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

        // RPID configures the Relying Party Server ID. This should generally be the origin without a scheme and port.
        std::string RPID;
        // RPDisplayName configures the display name for the Relying Party Server. This can be any string.
        std::string  RPDisplayName;
        // RPOrigins configures the list of Relying Party Server Origins that are permitted. These should be fully
        // qualified origins.
        std::vector<std::string> RPOrigins;
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
} // namespace WebAuthN::WebAuthN

#pragma GCC visibility pop

#endif /* WEBAUTHN_WEBAUTHN_CONFIG_IPP */
