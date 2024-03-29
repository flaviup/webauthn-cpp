workspace "webauthn-cpp"
    configurations {
        "StaticLib-Debug", 
        "StaticLib-Release",
        "SharedLib-Debug", 
        "SharedLib-Release"
    }

project "webauthn-cpp"
    architecture "x64" -- or ARM64
    language "C++"
    cppdialect "C++20" -- or gnu++20 or Default
    stl "libc++"
    toolset "gcc" -- or clang
    targetdir "bin/%{cfg.buildcfg}"
    
    files { 
        "**.hpp",
        "**.hh",
        "**.h",
        "**.ipp",
        "**.cpp", 
        "**.cc",
        "**.c"
    }

    removefiles { "**/test/**" }

    includedirs {
        "WebAuthN/Util/tpm2-tss",
        "WebAuthN/Util/tpm2-tss/tss2"
    }

    externalincludedirs {
        "/usr/include",
        "/usr/local/include"
    }

    links {
        "cbor",
        "crypto",
        "fmt",
        "icuuc",
        "jwt",
        "sodium",
        "ssl",
        "uuid"
    }

    defines {
        "MAXLOGLEVEL=4"
    }

    syslibdirs {
        "/usr/lib",
        "/usr/local/lib"
    }
    
    filter "configurations:StaticLib-Debug"
        kind "StaticLib"
        defines { "DEBUG" }
        symbols "On"

    filter "configurations:StaticLib-Release"
        kind "StaticLib"
        defines { "NDEBUG" }
        optimize "On"

    filter "configurations:SharedLib-Debug"
        kind "SharedLib"
        defines { "DEBUG" }
        symbols "On"
        targetsuffix ".1.0.0"

    filter "configurations:SharedLib-Release"
        kind "SharedLib"
        defines { "NDEBUG" }
        optimize "On"
        targetsuffix ".1.0.0"

    filter { "system:linux" }
        syslibdirs {
            "/usr/lib64",
            "/usr/local/lib64"
        }

    filter { "system:macosx" }
        externalincludedirs {
            "/usr/local/opt/icu4c/include"
        }
        links {
            "Cocoa.framework"
        }
        syslibdirs {
            "/usr/local/opt/icu4c/lib"
        }
