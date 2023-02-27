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
        "**.ipp",
        "**.cpp", 
        "**.cc"
    }

    removefiles { "**/test/**" }

    externalincludedirs {
        "/usr/local/opt/icu4c/include",
        "/usr/include",
        "/usr/local/include"
    }

    links {
        "cbor",
        "crypto",
        "fmt",
        "sodium",
        "ssl",
        "uuid"
    }

    syslibdirs {
        "/usr/local/opt/icu4c/lib",
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

    filter "configurations:SharedLib-Release"
        kind "SharedLib"
        defines { "NDEBUG" }
        optimize "On"

    filter { "system:not macosx" }
        links { "icu" }

    filter { "system:macosx" }
        links {
            "icuuc",
            "Cocoa.framework"
        }
