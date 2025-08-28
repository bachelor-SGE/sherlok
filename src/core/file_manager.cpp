#include "file_manager.h"
#include "../utils/file_utils.h"
#include <fstream>
#include <filesystem>
#include <algorithm>

namespace core {

FileManager::FileManager() {
    
}

std::vector<uint8_t> FileManager::readFile(const std::string& filePath) {
    try {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            lastError_ = "Не удалось открыть файл для чтения: " + filePath;
            return {};
        }

        
        auto fileSize = file.tellg();
        if (fileSize <= 0) {
            lastError_ = "Файл пуст или имеет недопустимый размер: " + filePath;
            return {};
        }

        
        file.seekg(0, std::ios::beg);

        
        std::vector<uint8_t> data(fileSize);
        file.read(reinterpret_cast<char*>(data.data()), fileSize);

        if (file.gcount() != fileSize) {
            lastError_ = "Ошибка чтения файла: " + filePath;
            return {};
        }

        return data;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при чтении файла: " + std::string(e.what());
        return {};
    }
}

bool FileManager::writeFile(const std::string& filePath, const std::vector<uint8_t>& data) {
    try {
        
        if (!ensureDirectoryExists(filePath)) {
            lastError_ = "Не удалось создать директорию для файла: " + filePath;
            return false;
        }

        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            lastError_ = "Не удалось открыть файл для записи: " + filePath;
            return false;
        }

        
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));

        if (!file.good()) {
            lastError_ = "Ошибка записи в файл: " + filePath;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при записи файла: " + std::string(e.what());
        return false;
    }
}

bool FileManager::fileExists(const std::string& filePath) const {
    try {
        return std::filesystem::exists(filePath) && std::filesystem::is_regular_file(filePath);
    }
    catch (...) {
        return false;
    }
}

int64_t FileManager::getFileSize(const std::string& filePath) const {
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

bool FileManager::createBackup(const std::string& filePath, const std::string& backupPath) {
    try {
        if (!fileExists(filePath)) {
            lastError_ = "Исходный файл не существует: " + filePath;
            return false;
        }

        
        if (!ensureDirectoryExists(backupPath)) {
            lastError_ = "Не удалось создать директорию для резервной копии: " + backupPath;
            return false;
        }

        
        std::filesystem::copy_file(filePath, backupPath, std::filesystem::copy_options::overwrite_existing);
        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при создании резервной копии: " + std::string(e.what());
        return false;
    }
}

bool FileManager::restoreFromBackup(const std::string& backupPath, const std::string& filePath) {
    try {
        if (!fileExists(backupPath)) {
            lastError_ = "Резервная копия не существует: " + backupPath;
            return false;
        }

        
        if (!ensureDirectoryExists(filePath)) {
            lastError_ = "Не удалось создать директорию для восстановления: " + filePath;
            return false;
        }

        
        std::filesystem::copy_file(backupPath, filePath, std::filesystem::copy_options::overwrite_existing);
        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при восстановлении из резервной копии: " + std::string(e.what());
        return false;
    }
}

std::vector<std::string> FileManager::getFilesInDirectory(const std::string& directoryPath, bool recursive) {
    std::vector<std::string> files;
    
    try {
        if (!std::filesystem::exists(directoryPath) || !std::filesystem::is_directory(directoryPath)) {
            lastError_ = "Директория не существует или не является директорией: " + directoryPath;
            return files;
        }

        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path().string());
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path().string());
                }
            }
        }
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при получении списка файлов: " + std::string(e.what());
    }

    return files;
}

std::string FileManager::getLastError() const {
    return lastError_;
}

bool FileManager::checkFilePermissions(const std::string& filePath) const {
    try {
        if (!fileExists(filePath)) {
            return false;
        }

        
        std::ifstream testFile(filePath);
        if (!testFile.is_open()) {
            return false;
        }
        testFile.close();

        return true;
    }
    catch (...) {
        return false;
    }
}

bool FileManager::ensureDirectoryExists(const std::string& directoryPath) const {
    try {
        std::filesystem::path path(directoryPath);
        auto parentPath = path.parent_path();
        
        if (!parentPath.empty() && !std::filesystem::exists(parentPath)) {
            std::filesystem::create_directories(parentPath);
        }
        
        return true;
    }
    catch (...) {
        return false;
    }
}

} 
