#pragma once

#include <string>

namespace utils {

enum class OperatingSystem {
    Windows,
    MacOS,
    Linux,
    Unknown
};

OperatingSystem detectOperatingSystem();

// Returns human-readable OS name
std::string getOperatingSystemName();

// Ensure application auto-start on login for current OS.
// Returns true if configured (or already configured), false otherwise.
bool ensureAutostart();

// Returns absolute path to current executable if available; empty string on failure.
std::string getExecutablePath();

}


