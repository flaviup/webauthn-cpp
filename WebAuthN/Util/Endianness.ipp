//
//  Endianness.ipp
//  webauthn-cpp
//
//  Created by Flaviu Pasca on 02/26/23.
//  flaviup on gmail com
//

#ifndef WEBAUTHN_UTIL_ENDIANNESS_IPP
#define WEBAUTHN_UTIL_ENDIANNESS_IPP

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
    defined(__BIG_ENDIAN__) ||                               \
    defined(__ARMEB__) ||                                    \
    defined(__THUMBEB__) ||                                  \
    defined(__AARCH64EB__) ||                                \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__LITTLE_ENDIAN__) ||                                 \
    defined(__ARMEL__) ||                                         \
    defined(__THUMBEL__) ||                                       \
    defined(__AARCH64EL__) ||                                     \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__) || \
    defined(_WIN32) || defined(__i386__) || defined(__x86_64__) || \
    defined(_X86_) || defined(_IA64_)
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#else
#error "This is an unknown architecture."
#endif

#define MAKE_UINT64(byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7) static_cast<uint64_t>((static_cast<uint64_t>(byte0) << 56ULL) | (static_cast<uint64_t>(byte1) << 48ULL) | (static_cast<uint64_t>(byte2) << 40ULL) | (static_cast<uint64_t>(byte3) << 32ULL) | (static_cast<uint64_t>(byte4) << 24ULL) | (static_cast<uint64_t>(byte5) << 16ULL) | (static_cast<uint64_t>(byte6) << 8ULL) | static_cast<uint64_t>(byte7))
#define MAKE_UINT32(byte0, byte1, byte2, byte3) static_cast<uint32_t>((static_cast<uint32_t>(byte0) << 24) | (static_cast<uint32_t>(byte1) << 16) | (static_cast<uint32_t>(byte2) << 8) | static_cast<uint32_t>(byte3))
#define MAKE_UINT16(byte0, byte1) static_cast<uint16_t>((static_cast<uint16_t>(byte0) << 8) | static_cast<uint16_t>(byte1))

#endif // WEBAUTHN_UTIL_ENDIANNESS_IPP
