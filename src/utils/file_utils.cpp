#include "file_utils.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <regex>

namespace utils {

FileUtils::FileUtils() {
    
}

bool FileUtils::fileExists(const std::string& filePath) const {
    try {
        return std::filesystem::exists(filePath) && std::filesystem::is_regular_file(filePath);
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::directoryExists(const std::string& dirPath) const {
    try {
        return std::filesystem::exists(dirPath) && std::filesystem::is_directory(dirPath);
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::createDirectory(const std::string& dirPath, bool createParents) const {
    try {
        if (createParents) {
            std::filesystem::create_directories(dirPath);
        } else {
            std::filesystem::create_directory(dirPath);
        }
        return directoryExists(dirPath);
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::deleteFile(const std::string& filePath) const {
    try {
        if (fileExists(filePath)) {
            return std::filesystem::remove(filePath);
        }
        return true; 
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::deleteDirectory(const std::string& dirPath, bool recursive) const {
    try {
        if (directoryExists(dirPath)) {
            if (recursive) {
                std::filesystem::remove_all(dirPath);
            } else {
                std::filesystem::remove(dirPath);
            }
        }
        return !directoryExists(dirPath);
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::copyFile(const std::string& sourcePath, const std::string& destPath, bool overwrite) const {
    try {
        if (!fileExists(sourcePath)) {
            return false;
        }

        
        auto destDir = std::filesystem::path(destPath).parent_path();
        if (!destDir.empty() && !directoryExists(destDir.string())) {
            if (!createDirectory(destDir.string(), true)) {
                return false;
            }
        }

        if (overwrite) {
            std::filesystem::copy_file(sourcePath, destPath, std::filesystem::copy_options::overwrite_existing);
        } else {
            std::filesystem::copy_file(sourcePath, destPath);
        }

        return fileExists(destPath);
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::moveFile(const std::string& sourcePath, const std::string& destPath) const {
    try {
        if (!fileExists(sourcePath)) {
            return false;
        }

        
        auto destDir = std::filesystem::path(destPath).parent_path();
        if (!destDir.empty() && !directoryExists(destDir.string())) {
            if (!createDirectory(destDir.string(), true)) {
                return false;
            }
        }

        std::filesystem::rename(sourcePath, destPath);
        return fileExists(destPath) && !fileExists(sourcePath);
    }
    catch (...) {
        return false;
    }
}

int64_t FileUtils::getFileSize(const std::string& filePath) const {
    try {
        if (!fileExists(filePath)) {
            return -1;
        }
        return static_cast<int64_t>(std::filesystem::file_size(filePath));
    }
    catch (...) {
        return -1;
    }
}

int64_t FileUtils::getFileModificationTime(const std::string& filePath) const {
    try {
        if (!fileExists(filePath)) {
            return -1;
        }
        
        auto time = std::filesystem::last_write_time(filePath);
        auto duration = time.time_since_epoch();
        auto system_time = std::chrono::system_clock::time_point(duration);
        return std::chrono::system_clock::to_time_t(system_time);
    }
    catch (...) {
        return -1;
    }
}

std::string FileUtils::getFileExtension(const std::string& filePath) const {
    try {
        std::filesystem::path path(filePath);
        return path.extension().string().substr(1); 
    }
    catch (...) {
        return "";
    }
}

std::string FileUtils::getFileName(const std::string& filePath) const {
    try {
        std::filesystem::path path(filePath);
        return path.filename().string();
    }
    catch (...) {
        return "";
    }
}

std::string FileUtils::getDirectoryPath(const std::string& filePath) const {
    try {
        std::filesystem::path path(filePath);
        return path.parent_path().string();
    }
    catch (...) {
        return "";
    }
}

std::string FileUtils::getAbsolutePath(const std::string& filePath) const {
    try {
        std::filesystem::path path(filePath);
        return std::filesystem::absolute(path).string();
    }
    catch (...) {
        return filePath;
    }
}

std::string FileUtils::normalizePath(const std::string& filePath) const {
    try {
        std::filesystem::path path(filePath);
        return path.lexically_normal().string();
    }
    catch (...) {
        return filePath;
    }
}

std::string FileUtils::joinPath(const std::vector<std::string>& parts) const {
    try {
        if (parts.empty()) {
            return "";
        }

        std::filesystem::path result = parts[0];
        for (size_t i = 1; i < parts.size(); ++i) {
            result /= parts[i];
        }

        return result.string();
    }
    catch (...) {
        return "";
    }
}

std::vector<std::string> FileUtils::getFilesInDirectory(const std::string& dirPath, const std::string& pattern, bool recursive) const {
    std::vector<std::string> files;
    
    try {
        if (!directoryExists(dirPath)) {
            return files;
        }

        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
                if (entry.is_regular_file() && matchesPattern(entry.path().filename().string(), pattern)) {
                    files.push_back(entry.path().string());
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                if (entry.is_regular_file() && matchesPattern(entry.path().filename().string(), pattern)) {
                    files.push_back(entry.path().string());
                }
            }
        }
    }
    catch (...) {
        
    }

    return files;
}

bool FileUtils::checkFilePermissions(const std::string& filePath, bool checkRead, bool checkWrite) const {
    try {
        if (!fileExists(filePath)) {
            return false;
        }

        if (checkRead) {
            std::ifstream testFile(filePath);
            if (!testFile.is_open()) {
                return false;
            }
            testFile.close();
        }

        if (checkWrite) {
            std::ofstream testFile(filePath, std::ios::app);
            if (!testFile.is_open()) {
                return false;
            }
            testFile.close();
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool FileUtils::isAbsolutePath(const std::string& filePath) const {
    try {
        std::filesystem::path path(filePath);
        return path.is_absolute();
    }
    catch (...) {
        return false;
    }
}

std::vector<std::string> FileUtils::splitPath(const std::string& filePath) const {
    std::vector<std::string> parts;
    
    try {
        std::filesystem::path path(filePath);
        
        for (const auto& part : path) {
            if (!part.string().empty()) {
                parts.push_back(part.string());
            }
        }
    }
    catch (...) {
        
    }

    return parts;
}

bool FileUtils::matchesPattern(const std::string& fileName, const std::string& pattern) const {
    try {
        if (pattern == "*" || pattern.empty()) {
            return true;
        }

        
        if (pattern.find('*') != std::string::npos) {
            
            std::string regexPattern = pattern;
            size_t pos = 0;
            while ((pos = regexPattern.find('*', pos)) != std::string::npos) {
                regexPattern.replace(pos, 1, ".*");
                pos += 2;
            }

            std::regex regex(regexPattern);
            return std::regex_match(fileName, regex);
        } else {
            return fileName == pattern;
        }
    }
    catch (...) {
        return false;
    }
}

} 
