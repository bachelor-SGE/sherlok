cmake_minimum_required(VERSION 3.15)
project(FileEncryptionDemo)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(MSVC)
    if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endif()
option(BUILD_TESTS "Build tests" OFF)
option(USE_OPENSSL "Use OpenSSL for cryptography" ON)
if(APPLE)
    enable_language(OBJCXX)
endif()
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DUNICODE)
    add_definitions(-D_UNICODE)
endif()
find_package(PkgConfig QUIET)
if(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    add_definitions(-DUSE_OPENSSL)
endif()
set(SOURCES
    src/main.cpp
    src/core/encryption_service.cpp
    src/core/file_manager.cpp
    src/crypto/aes_crypto.cpp
    src/crypto/key_manager.cpp
    src/ui/main_window.cpp
    src/ui/encryption_dialog.cpp
    src/ui/password_lock.cpp
    src/utils/logger.cpp
    src/utils/file_utils.cpp
    src/utils/platform.cpp
)
set(HEADERS
    src/core/encryption_service.h
    src/core/file_manager.h
    src/crypto/aes_crypto.h
    src/crypto/key_manager.h
    src/ui/main_window.h
    src/ui/encryption_dialog.h
    src/ui/password_lock.h
    src/utils/logger.h
    src/utils/file_utils.h
    src/utils/platform.h
)
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME} PRIVATE
    src/
    src/core/
    src/crypto/
    src/ui/
    src/utils/
)
if(USE_OPENSSL)
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        user32
        gdi32
        comctl32
        comdlg32
        shell32
        advapi32
        crypt32
        ole32
        oleaut32
    )
elseif(APPLE)
    find_library(COCOA_FRAMEWORK Cocoa)
    if(COCOA_FRAMEWORK)
        target_sources(${PROJECT_NAME} PRIVATE src/ui/password_lock_mac.mm)
        target_link_libraries(${PROJECT_NAME} PRIVATE ${COCOA_FRAMEWORK})
    endif()
elseif(UNIX)
    find_package(PkgConfig QUIET)
    find_path(X11_INCLUDE_DIR X11/Xlib.h)
    find_library(X11_LIB X11)
    if(X11_INCLUDE_DIR AND X11_LIB)
        target_include_directories(${PROJECT_NAME} PRIVATE ${X11_INCLUDE_DIR})
        target_link_libraries(${PROJECT_NAME} PRIVATE ${X11_LIB})
    endif()
endif()
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
install(FILES README.md
    DESTINATION share/${PROJECT_NAME}
)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
