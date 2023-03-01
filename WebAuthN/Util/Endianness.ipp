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

#define MAKE_UINT32(a, b, c, d) ((static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) | (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d))
#define MAKE_UINT16(a, b) ((static_cast<uint16_t>(a) << 8) | static_cast<uint16_t>(b))

#endif // WEBAUTHN_UTIL_ENDIANNESS_IPP
