//
//  WebAuthNCBOR.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/26/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_WEBAUTHNCBOR_IPP
#define WEBAUTHN_PROTOCOL_WEBAUTHNCBOR_IPP

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol::WebAuthNCBOR {

    using json = nlohmann::json;

    inline constexpr const auto NESTED_LEVELS_ALLOWED = 4;

    // ctap2CBORDecMode is the cbor.DecMode following the CTAP2 canonical CBOR encoding form
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    /*var ctap2CBORDecMode, _ = cbor.DecOptions{
        DupMapKey:       cbor.DupMapKeyEnforcedAPF,
        MaxNestedLevels: NESTED_LEVELS_ALLOWED,
        IndefLength:     cbor.IndefLengthForbidden,
        TagsMd:          cbor.TagsForbidden,
    }.DecMode()

    var ctap2CBOREncMode, _ = cbor.CTAP2EncOptions().EncMode()*/

    // Unmarshal parses the CBOR-encoded data into the value pointed to by v
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<json> JsonUnmarshal(const std::vector<uint8_t>& data) {

        json v;
        //ctap2CBORDecMode.Unmarshal(data, v);

        return json::from_cbor(data);
    }

    // Marshal encodes the value pointed to by v
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<std::vector<uint8_t>> JsonMarshal(const json& v) {

        //return ctap2CBOREncMode.Marshal(v);
        auto val = json::to_cbor(v);
        return val;
    }





    // ctap2CBORDecMode is the cbor.DecMode following the CTAP2 canonical CBOR encoding form
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    /*var ctap2CBORDecMode, _ = cbor.DecOptions{
        DupMapKey:       cbor.DupMapKeyEnforcedAPF,
        MaxNestedLevels: nestedLevelsAllowed,
        IndefLength:     cbor.IndefLengthForbidden,
        TagsMd:          cbor.TagsForbidden,
    }.DecMode()

    var ctap2CBOREncMode, _ = cbor.CTAP2EncOptions().EncMode()

    // Unmarshal parses the CBOR-encoded data into the value pointed to by v
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<std::any> Unmarshal(const std::vector<uint8_t>& data) {
        return ctap2CBORDecMode.Unmarshal(data, v);
    }

    // Marshal encodes the value pointed to by v
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<std::vector<uint8_t>> Marshal(std::any& v) {
        
        return ctap2CBOREncMode.Marshal(v);
    }*/
} // namespace WebAuthN::Protocol::WebAuthNCBOR

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_WEBAUTHNCBOR_IPP */