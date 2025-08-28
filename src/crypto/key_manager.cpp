#include "key_manager.h"
#include "../utils/file_utils.h"
#include <fstream>
#include <filesystem>
#include <random>
#include <iomanip>
#include <sstream>

namespace crypto {

KeyManager::KeyManager() {
    
    storagePath_ = std::filesystem::current_path().string() + "/keys";
    ensureStorageDirectoryExists();
}

std::string KeyManager::generateKey(size_t keyLength) {
    try {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(33, 126); 

        std::string key;
        key.reserve(keyLength);

        for (size_t i = 0; i < keyLength; ++i) {
            key += static_cast<char>(dis(gen));
        }

        return key;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при генерации ключа: " + std::string(e.what());
        return "";
    }
}

bool KeyManager::storeKey(const std::string& keyId, const std::string& key, const std::string& password) {
    try {
        if (keyId.empty() || key.empty() || password.empty()) {
            lastError_ = "Идентификатор ключа, ключ и пароль не могут быть пустыми";
            return false;
        }

        
        if (!ensureStorageDirectoryExists()) {
            lastError_ = "Не удалось создать директорию для хранения ключей";
            return false;
        }

        
        auto encryptedKey = encryptForStorage(
            std::vector<uint8_t>(key.begin(), key.end()), 
            password
        );

        if (encryptedKey.empty()) {
            lastError_ = "Не удалось зашифровать ключ для хранения";
            return false;
        }

        
        std::string keyFilePath = getKeyFilePath(keyId);
        std::ofstream keyFile(keyFilePath, std::ios::binary);
        
        if (!keyFile.is_open()) {
            lastError_ = "Не удалось открыть файл для записи ключа: " + keyFilePath;
            return false;
        }

        keyFile.write(reinterpret_cast<const char*>(encryptedKey.data()), 
                     static_cast<std::streamsize>(encryptedKey.size()));

        if (!keyFile.good()) {
            lastError_ = "Ошибка записи ключа в файл: " + keyFilePath;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при сохранении ключа: " + std::string(e.what());
        return false;
    }
}

std::string KeyManager::retrieveKey(const std::string& keyId, const std::string& password) {
    try {
        if (keyId.empty() || password.empty()) {
            lastError_ = "Идентификатор ключа и пароль не могут быть пустыми";
            return "";
        }

        std::string keyFilePath = getKeyFilePath(keyId);
        
        if (!std::filesystem::exists(keyFilePath)) {
            lastError_ = "Ключ не найден: " + keyId;
            return "";
        }

        
        std::ifstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile.is_open()) {
            lastError_ = "Не удалось открыть файл ключа для чтения: " + keyFilePath;
            return "";
        }

        
        keyFile.seekg(0, std::ios::end);
        auto fileSize = keyFile.tellg();
        keyFile.seekg(0, std::ios::beg);

        if (fileSize <= 0) {
            lastError_ = "Файл ключа пуст или имеет недопустимый размер: " + keyFilePath;
            return "";
        }

        
        std::vector<uint8_t> encryptedKey(fileSize);
        keyFile.read(reinterpret_cast<char*>(encryptedKey.data()), fileSize);

        if (keyFile.gcount() != fileSize) {
            lastError_ = "Ошибка чтения файла ключа: " + keyFilePath;
            return "";
        }

        
        auto decryptedKey = decryptFromStorage(encryptedKey, password);
        if (decryptedKey.empty()) {
            lastError_ = "Не удалось дешифровать ключ";
            return "";
        }

        return std::string(decryptedKey.begin(), decryptedKey.end());
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при извлечении ключа: " + std::string(e.what());
        return "";
    }
}

bool KeyManager::deleteKey(const std::string& keyId, const std::string& password) {
    try {
        if (keyId.empty() || password.empty()) {
            lastError_ = "Идентификатор ключа и пароль не могут быть пустыми";
            return false;
        }

        
        auto retrievedKey = retrieveKey(keyId, password);
        if (retrievedKey.empty()) {
            lastError_ = "Не удалось проверить ключ для удаления";
            return false;
        }

        
        std::string keyFilePath = getKeyFilePath(keyId);
        if (std::filesystem::exists(keyFilePath)) {
            std::filesystem::remove(keyFilePath);
        }

        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при удалении ключа: " + std::string(e.what());
        return false;
    }
}

bool KeyManager::keyExists(const std::string& keyId) const {
    try {
        if (keyId.empty()) {
            return false;
        }

        std::string keyFilePath = getKeyFilePath(keyId);
        return std::filesystem::exists(keyFilePath) && std::filesystem::is_regular_file(keyFilePath);
    }
    catch (...) {
        return false;
    }
}

std::vector<std::string> KeyManager::listKeys() const {
    std::vector<std::string> keys;
    
    try {
        if (!std::filesystem::exists(storagePath_) || !std::filesystem::is_directory(storagePath_)) {
            return keys;
        }

        for (const auto& entry : std::filesystem::directory_iterator(storagePath_)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                
                if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".key") {
                    keys.push_back(filename.substr(0, filename.length() - 4));
                } else {
                    keys.push_back(filename);
                }
            }
        }
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при получении списка ключей: " + std::string(e.what());
    }

    return keys;
}

std::string KeyManager::exportKey(const std::string& keyId, const std::string& password) {
    try {
        auto key = retrieveKey(keyId, password);
        if (key.empty()) {
            lastError_ = "Не удалось извлечь ключ для экспорта";
            return "";
        }

        
        std::stringstream ss;
        for (char c : key) {
            ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
        
        return ss.str();
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при экспорте ключа: " + std::string(e.what());
        return "";
    }
}

bool KeyManager::importKey(const std::string& keyId, const std::string& exportedKey, const std::string& password) {
    try {
        if (exportedKey.empty() || exportedKey.length() % 2 != 0) {
            lastError_ = "Неверный формат экспортированного ключа";
            return false;
        }

        
        std::string key;
        for (size_t i = 0; i < exportedKey.length(); i += 2) {
            std::string byteString = exportedKey.substr(i, 2);
            char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
            key += byte;
        }

        
        return storeKey(keyId, key, password);
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при импорте ключа: " + std::string(e.what());
        return false;
    }
}

std::string KeyManager::getLastError() const {
    return lastError_;
}

std::vector<uint8_t> KeyManager::encryptForStorage(const std::vector<uint8_t>& data, const std::string& password) {
    try {
        if (data.empty() || password.empty()) {
            return {};
        }

        
        std::vector<uint8_t> encryptedData;
        
        
        const std::vector<uint8_t> signature = {0x4B, 0x45, 0x59, 0x53, 0x54, 0x4F, 0x52, 0x45};
        encryptedData.insert(encryptedData.end(), signature.begin(), signature.end());
        
        
        uint32_t dataSize = static_cast<uint32_t>(data.size());
        for (int i = 0; i < 4; ++i) {
            encryptedData.push_back(static_cast<uint8_t>((dataSize >> (i * 8)) & 0xFF));
        }
        
        
        for (size_t i = 0; i < data.size(); ++i) {
            encryptedData.push_back(data[i] ^ static_cast<uint8_t>(password[i % password.length()]));
        }

        return encryptedData;
    }
    catch (...) {
        return {};
    }
}

std::vector<uint8_t> KeyManager::decryptFromStorage(const std::vector<uint8_t>& encryptedData, const std::string& password) {
    try {
        if (encryptedData.size() < 12) { 
            return {};
        }

        
        const std::vector<uint8_t> expectedSignature = {0x4B, 0x45, 0x59, 0x53, 0x54, 0x4F, 0x52, 0x45};
        for (size_t i = 0; i < expectedSignature.size(); ++i) {
            if (encryptedData[i] != expectedSignature[i]) {
                return {};
            }
        }

        
        uint32_t dataSize = 0;
        for (int i = 0; i < 4; ++i) {
            dataSize |= static_cast<uint32_t>(encryptedData[8 + i]) << (i * 8);
        }

        if (dataSize > encryptedData.size() - 12) {
            return {};
        }

        
        std::vector<uint8_t> decryptedData;
        decryptedData.reserve(dataSize);

        for (size_t i = 0; i < dataSize; ++i) {
            decryptedData.push_back(encryptedData[12 + i] ^ static_cast<uint8_t>(password[i % password.length()]));
        }

        return decryptedData;
    }
    catch (...) {
        return {};
    }
}

std::string KeyManager::getKeyFilePath(const std::string& keyId) const {
    return storagePath_ + "/" + keyId + ".key";
}

bool KeyManager::ensureStorageDirectoryExists() const {
    try {
        if (!std::filesystem::exists(storagePath_)) {
            std::filesystem::create_directories(storagePath_);
        }
        return std::filesystem::exists(storagePath_) && std::filesystem::is_directory(storagePath_);
    }
    catch (...) {
        return false;
    }
}

} 
