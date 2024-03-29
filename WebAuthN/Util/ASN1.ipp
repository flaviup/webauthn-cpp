//
//  ASN1.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 03/21/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_ASN1_IPP
#define WEBAUTHN_UTIL_ASN1_IPP

#include <string>
#include <vector>
#include <tuple>
#include <openssl/asn1.h>
#include "../Core.ipp"

#pragma GCC visibility push(default)

namespace WebAuthN::Util::ASN1 {

    using namespace std::string_literals;

    class OIDType final {

    public:

        OIDType() noexcept :
            _obj(nullptr) {
        }

        OIDType(const std::string& str) :
            _obj(nullptr) {
            _Parse(str);
        }

        OIDType(const OIDType& oid) {

            if (this != &oid) {

                if (oid._obj != nullptr) {

                    _obj = OBJ_dup(oid._obj);

                    if (_obj == nullptr) {
                        throw std::bad_alloc();
                    }
                } else {
                    _obj = nullptr;
                }
            }
        }

        OIDType(OIDType&& oid) noexcept:
            _obj(std::move(oid._obj)) {
        }

        ~OIDType() noexcept {

            if (_obj != nullptr) {

                ASN1_OBJECT_free(_obj);
                _obj = nullptr;
            }
        }

        inline OIDType& operator =(const OIDType& other) {

            if (this != &other) {

                if (_obj != nullptr) {

                    ASN1_OBJECT_free(_obj);
                    _obj = nullptr;
                }

                if (other._obj != nullptr) {

                    _obj = OBJ_dup(other._obj);

                    if (_obj == nullptr) {
                        throw std::bad_alloc();
                    }
                } else {
                    _obj = nullptr;
                }
            }

            return *this;
        }

        inline OIDType& operator =(OIDType&& other) noexcept {

            std::swap(_obj, other._obj);
            return *this;
        }

        inline constexpr bool operator ==(const OIDType& other) const noexcept {

            if (_obj == other._obj) {
                return true;
            } else if (_obj != nullptr && other._obj != nullptr) {

                const auto data1 = OBJ_get0_data(_obj);
                const auto data2 = OBJ_get0_data(other._obj);

                if (data1 == data2) {
                    return true;
                } else if (data1 != nullptr && data2 != nullptr) {

                    auto p1 = data1;
                    auto p2 = data2;

                    while ((*p1 != 0) && (*p2 != 0) && (*p1 == *p2)) {

                        ++p1;
                        ++p2;
                    }

                    return ((*p1 == 0) && (*p2 == 0));
                }
            }

            return false;
        }

        inline constexpr bool operator !=(const OIDType& other) const noexcept {

            return !(*this == other);
        }

        inline bool Equals(const std::string& data) const noexcept {

            if (_obj == nullptr && data.empty()) {
                return true;
            } else if (_obj != nullptr) {

                const auto data1 = OBJ_get0_data(_obj);

                if (data1 == nullptr && data.empty()) {
                    return true;
                } else if (data1 != nullptr) {

                    auto p1 = data1;
                    auto p2 = data.data();
                    auto end = p2 + data.size();

                    while ((*p1 != 0) && (p2 < end) && (*p1 == static_cast<unsigned char>(*p2))) {

                        ++p1;
                        ++p2;
                    }

                    return ((*p1 == 0) && (p2 == end));
                }
            }

            return false;
        }

        inline bool Equals(const std::vector<uint8_t>& data) const noexcept {

            if (_obj == nullptr && data.empty()) {
                return true;
            } else if (_obj != nullptr) {

                const auto data1 = OBJ_get0_data(_obj);

                if (data1 == nullptr && data.empty()) {
                    return true;
                } else if (data1 != nullptr) {

                    auto p1 = data1;
                    auto p2 = data.data();
                    auto end = p2 + data.size();

                    while ((*p1 != 0) && (p2 < end) && (*p1 == *p2)) {

                        ++p1;
                        ++p2;
                    }

                    return ((*p1 == 0) && (p2 == end));
                }
            }

            return false;
        }

    private:

        inline void _Parse(const std::string& str) {

            if (str.empty()) {
                return;
            }
            _obj = OBJ_txt2obj(str.data(), 1);

            if (_obj == nullptr) {
                throw std::invalid_argument("Invalid oid "s + str);
            }
        }

        ASN1_OBJECT* _obj{nullptr};
    };

    inline expected<long> GetSequence(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SEQUENCE) {
            return MakeError(ErrorType("Could not parse ASN1 data as sequence"s));
        }

        return length;
    }

    inline expected<long> GetBooleanSequence(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if ((ret != V_ASN1_CONSTRUCTED && ret != 0) || tagID != V_ASN1_BOOLEAN) {
            return MakeError(ErrorType("Could not parse ASN1 data as boolean"s));
        }

        return length;
    }

    inline long TryGetSequence(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto p = data;
        auto ret = ASN1_get_object(&p, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SEQUENCE) {
            return 0;
        }
        data = p;

        return length;
    }

    inline expected<long> GetSet(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SET) {
            return MakeError(ErrorType("Could not parse ASN1 data as set"s));
        }

        return length;
    }

    inline long TryGetSet(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto p = data;
        auto ret = ASN1_get_object(&p, &length, &tagID, &classID, 1L << 24);

        if (ret != V_ASN1_CONSTRUCTED || tagID != V_ASN1_SET) {
            return 0;
        }
        data = p;

        return length;
    }

    template<typename T = int32_t>
    inline expected<T> GetInt(const uint8_t*& data, int* tag = nullptr) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if (ret == 0 && tagID == V_ASN1_NULL) {

            data += length;

            if (tag != nullptr) {
                *tag = tagID;
            }

            return static_cast<T>(0);
        }

        if (ret != 0 || length < 1 || (tagID != V_ASN1_INTEGER && tagID != V_ASN1_ENUMERATED && tagID != V_ASN1_BOOLEAN)) {
            return MakeError(ErrorType("Could not parse ASN1 data as int"s));
        }

        auto value = length > 7 ? MAKE_UINT64(data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]) :
                                  length > 6 ? MAKE_UINT64(0, data[0], data[1], data[2], data[3], data[4], data[5], data[6]) :
                                               length > 5 ? MAKE_UINT64(0, 0, data[0], data[1], data[2], data[3], data[4], data[5]) :
                                                            length > 4 ? MAKE_UINT64(0, 0, 0, data[0], data[1], data[2], data[3], data[4]) :
                                                            length > 2 ? MAKE_UINT32(length == 4 ? data[0] : 0, length == 4 ? data[1] : data[0], length == 4 ? data[2] : data[1], length == 4 ? data[3] : data[2]) :
                                                                         length > 1 ? MAKE_UINT16(data[0], data[1]) :
                                                                                      data[0];
        data += length;

        if (tag != nullptr) {
            *tag = tagID;
        }

        return static_cast<T>(value);
    }

    inline expected<std::string> GetObject(const uint8_t*& data) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if ((ret & 0x80) || (ret == 0xa0) || tagID != V_ASN1_OBJECT) {
            return MakeError(ErrorType("Could not parse ASN1 data as object"s));
        }

        if (length == 0) {
            return ""s;
        }

        std::string retStr(data, data + length);
        data += length;

        return retStr;
    }

    inline expected<std::vector<uint8_t>> GetBytes(const uint8_t*& data, int* tag = nullptr) noexcept {

        auto length = 0L;
        auto tagID = 0, classID = 0;
        auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

        if ((ret & 0x80) || (ret == 0xa0)) {
            return MakeError(ErrorType("Could not parse ASN1 data as bytes"s));
        }
        auto value = length > 0 ? std::vector<uint8_t>(data, data + length) : std::vector<uint8_t>{};
        data += length;

        if (tag != nullptr) {
            *tag = tagID;
        }

        return value;
    }

    using BufferSliceType = std::tuple<const uint8_t*, size_t>;

    inline expected<std::map<int, BufferSliceType>>
    GetMap(const uint8_t*& data, const size_t size) noexcept {

        std::map<int, BufferSliceType> asn1Map{};
        auto end = data + size;

        while (data < end) {

            auto length = 0L;
            auto tagID = 0, classID = 0;
            auto ret = ASN1_get_object(&data, &length, &tagID, &classID, 1L << 24);

            if ((ret & 0x80) || (ret == 0xa0) || tagID == V_ASN1_EOC) {
                return MakeError(ErrorType("Could not parse ASN1 data"s));
            }
            asn1Map[tagID] = length > 0 ? BufferSliceType{data, length} : BufferSliceType{};
            data += length;
        }

        return asn1Map;
    }

    static inline expected<std::vector<uint8_t>>
    ToBytes(const BufferSliceType& bufferSlice) noexcept {

        if (std::get<size_t>(bufferSlice) < size_t(1)) {
            return std::vector<uint8_t>{};
        }
        auto p = std::get<const uint8_t*>(bufferSlice);

        return GetBytes(p);
    }

    static inline expected<bool>
    ToBool(const BufferSliceType& bufferSlice) noexcept {

        if (std::get<size_t>(bufferSlice) < size_t(1)) {
            return MakeError(ErrorType("Buffer slice is empty"s));
        }
        auto p = std::get<const uint8_t*>(bufferSlice);
        auto retInt = GetInt(p);

        if (retInt) {
            return retInt.value() != 0;
        }

        return MakeError(ErrorType("Could not parse ASN1 data as int32"s));
    }

    static inline expected<int32_t>
    ToInt32(const BufferSliceType& bufferSlice) noexcept {

        if (std::get<size_t>(bufferSlice) < size_t(1)) {
            return MakeError(ErrorType("Buffer slice is empty"s));
        }
        auto p = std::get<const uint8_t*>(bufferSlice);
        auto retInt = GetInt(p);

        if (retInt) {
            return retInt.value();
        }

        return MakeError(ErrorType("Could not parse ASN1 data as int32"s));
    }

    static inline expected<int64_t>
    ToInt64(const BufferSliceType& bufferSlice) noexcept {

        if (std::get<size_t>(bufferSlice) < size_t(1)) {
            return MakeError(ErrorType("Buffer slice is empty"s));
        }
        auto p = std::get<const uint8_t*>(bufferSlice);
        auto retInt = GetInt<int64_t>(p);

        if (retInt) {
            return retInt.value();
        }

        return MakeError(ErrorType("Could not parse ASN1 data as int64"s));
    }

    static inline expected<std::set<int32_t>>
    ToInt32Set(const BufferSliceType& bufferSlice) noexcept {

        if (std::get<size_t>(bufferSlice) < size_t(1)) {
            return MakeError(ErrorType("Buffer slice is empty"s));
        }
        auto p = std::get<const uint8_t*>(bufferSlice);
        auto end = p + std::get<size_t>(bufferSlice);
        auto retSet = GetSet(p);

        if (!retSet || p + retSet.value() != end) {
            return MakeError(ErrorType("Could not parse ASN1 data as set"s));
        }
        std::set<int32_t> value{};

        while (p < end) {

            auto retInt = GetInt(p);

            if (retInt) {
                value.insert(retInt.value());
            } else {
                return MakeError(ErrorType("Could not parse ASN1 data as set"s));
            }
        }

        return value;
    }

    template<typename T>
    static inline expected<T>
    ToIntEnum(const BufferSliceType& bufferSlice) noexcept {

        if (std::get<size_t>(bufferSlice) < size_t(1)) {
            return MakeError(ErrorType("Buffer slice is empty"s));
        }
        auto p = std::get<const uint8_t*>(bufferSlice);
        auto end = p + std::get<size_t>(bufferSlice);
        auto isSet = TryGetSet(p) != 0;

        if (isSet) {

            T t{0};

            while (p < end) {

                auto retInt = GetInt(p);

                if (retInt) {
                    t = static_cast<T>(static_cast<int>(t) | static_cast<int>(retInt.value()));
                } else {
                    return MakeError(ErrorType("Could not parse ASN1 data as int32"s));
                }
            }

            return t;
        } else {

            auto retInt = GetInt(p);

            if (retInt) {
                return static_cast<T>(static_cast<int>(retInt.value()));
            }
        }

        return MakeError(ErrorType("Could not parse ASN1 data as int32"s));
    }
} // namespace WebAuthN::Util::ASN1

#pragma GCC visibility pop

#endif /* WEBAUTHN_UTIL_ASN1_IPP */
