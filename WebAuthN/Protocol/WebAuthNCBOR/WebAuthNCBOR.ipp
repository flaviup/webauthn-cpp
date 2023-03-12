//
//  WebAuthNCBOR.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/26/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_PROTOCOL_WEBAUTHNCBOR_IPP
#define WEBAUTHN_PROTOCOL_WEBAUTHNCBOR_IPP

#include <sstream>
//#include <iostream>
#include <iomanip>

//#include <cstdio>
#include <cbor.h>

#include <nlohmann/json.hpp>
#include "../../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Protocol::WebAuthNCBOR {

    using json = nlohmann::json;

    inline constexpr const auto NESTED_LEVELS_ALLOWED = 4;

    inline std::string VectorUint8ToHexString(const std::vector<uint8_t>& v) {
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (const auto i : v) {
            ss << std::hex << std::setw(2) << static_cast<int>(i);
        }

        return ss.str();
    }

    // ctap2CBORDecMode is the cbor.DecMode following the CTAP2 canonical CBOR encoding form
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    /*var ctap2CBORDecMode, _ = cbor.DecOptions{
        DupMapKey:       cbor.DupMapKeyEnforcedAPF,
        MaxNestedLevels: NESTED_LEVELS_ALLOWED,
        IndefLength:     cbor.IndefLengthForbidden,
        TagsMd:          cbor.TagsForbidden,
    }.DecMode()

    var ctap2CBOREncMode, _ = cbor.CTAP2EncOptions().EncMode()*/

    // JsonUnmarshal parses the CBOR-encoded data into the returned JSON
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<json> JsonUnmarshal(const std::vector<uint8_t>& data) noexcept {

        try {
            //std::clog << std::endl << VectorUint8ToHexString(data);

            return json::from_cbor(data);
        } catch (const std::exception&) {

            return unexpected(std::string("JSON Unmarshal error"));
        }
    }

    // JsonMarshal CBOR-encodes the JSON referenced by v
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<std::vector<uint8_t>> JsonMarshal(const json& v) noexcept {

        try {

            return json::to_cbor(v);
        } catch (const std::exception&) {

            return unexpected(std::string("JSON Marshal error"));
        }
    }

    using CBORObjectType = cbor_item_t*;

    // Unmarshal parses the CBOR-encoded data into the returned value
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<CBORObjectType> Unmarshal(const std::vector<uint8_t>& data) noexcept {
        
        //std::clog << std::endl << VectorUint8ToHexString(data);
        
        struct cbor_load_result result;
        cbor_item_t* item = cbor_load(data.data(), data.size(), &result);

        if (item == nullptr) {

            return unexpected(std::string("Unmarshal error"));
        }

        /* Pretty-print the result */
        //cbor_describe(item, stdout);
        //fflush(stdout);
        /* Deallocate the result */

        return item;
    }

    // Marshal CBOR-encodes the value referenced by v
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<std::vector<uint8_t>> Marshal(CBORObjectType& v) noexcept {
        
        unsigned char* buffer = nullptr;
        size_t buffer_size{0};
        cbor_serialize_alloc(v, &buffer, &buffer_size);
        
        if (buffer != nullptr) {

            auto marshaled = std::vector<uint8_t>(buffer, buffer + buffer_size);
            free(buffer);
            cbor_decref(&v);
            //std::clog << std::endl << VectorUint8ToHexString(marshaled);

            return marshaled;
        } else {

            return unexpected(std::string("Marshal error"));
        }
    }

    // Remarshal parses the CBOR-encoded data and re-encodes it using CTAP2 rules
    // following the CTAP2 canonical CBOR encoding form.
    // (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
    inline expected<std::vector<uint8_t>> Remarshal(const std::vector<uint8_t>& data) noexcept {

        // TBD ....

        return data;
    }
} // namespace WebAuthN::Protocol::WebAuthNCBOR

#pragma GCC visibility pop

#endif /* WEBAUTHN_PROTOCOL_WEBAUTHNCBOR_IPP */
