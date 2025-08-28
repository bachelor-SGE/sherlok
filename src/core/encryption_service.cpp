#include "encryption_service.h"
#include "../crypto/aes_crypto.h"
#include "../crypto/key_manager.h"
#include "../core/file_manager.h"
#include "../utils/logger.h"

namespace core {

namespace {
}

EncryptionService::EncryptionService() {
    cryptoProvider_ = std::make_unique<crypto::AESCryptoProvider>();
    fileManager_ = std::make_unique<FileManager>();
}

bool EncryptionService::encryptFile(const std::string& filePath, const std::string& password) {
    try {
        
        if (!fileManager_->fileExists(filePath)) {
            lastError_ = "Файл не существует: " + filePath;
            return false;
        }

        
        auto fileData = fileManager_->readFile(filePath);
        if (fileData.empty()) {
            lastError_ = "Не удалось прочитать файл: " + filePath;
            return false;
        }

        
        std::string backupPath = filePath + ".backup";
        if (!fileManager_->createBackup(filePath, backupPath)) {
            lastError_ = "Не удалось создать резервную копию: " + filePath;
            return false;
        }

        
        auto encryptedData = cryptoProvider_->encrypt(fileData, password);
        if (encryptedData.empty()) {
            lastError_ = "Ошибка шифрования: " + cryptoProvider_->getLastError();
            return false;
        }

        
        if (!fileManager_->writeFile(filePath, encryptedData)) {
            lastError_ = "Не удалось записать зашифрованный файл: " + filePath;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при шифровании: " + std::string(e.what());
        return false;
    }
}

bool EncryptionService::decryptFile(const std::string& filePath, const std::string& password) {
    try {
        
        if (!fileManager_->fileExists(filePath)) {
            lastError_ = "Файл не существует: " + filePath;
            return false;
        }

        
        if (!isFileEncrypted(filePath)) {
            lastError_ = "Файл не зашифрован: " + filePath;
            return false;
        }

        
        auto encryptedData = fileManager_->readFile(filePath);
        if (encryptedData.empty()) {
            lastError_ = "Не удалось прочитать зашифрованный файл: " + filePath;
            return false;
        }

        
        auto decryptedData = cryptoProvider_->decrypt(encryptedData, password);
        if (decryptedData.empty()) {
            lastError_ = "Ошибка дешифрования: " + cryptoProvider_->getLastError();
            return false;
        }

        
        if (!fileManager_->writeFile(filePath, decryptedData)) {
            lastError_ = "Не удалось записать дешифрованный файл: " + filePath;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при дешифровании: " + std::string(e.what());
        return false;
    }
}

size_t EncryptionService::encryptFiles(const std::vector<std::string>& filePaths, const std::string& password) {
    size_t successCount = 0;
    
    for (const auto& filePath : filePaths) {
        if (encryptFile(filePath, password)) {
            successCount++;
        }
    }
    
    return successCount;
}

size_t EncryptionService::decryptFiles(const std::vector<std::string>& filePaths, const std::string& password) {
    size_t successCount = 0;
    
    for (const auto& filePath : filePaths) {
        if (decryptFile(filePath, password)) {
            successCount++;
        }
    }
    
    return successCount;
}

bool EncryptionService::isFileEncrypted(const std::string& filePath) const {
    try {
        
        
        
        if (!fileManager_->fileExists(filePath)) {
            return false;
        }
        
        auto fileData = fileManager_->readFile(filePath);
        if (fileData.size() < 16) {
            return false;
        }
        
        
        
        const std::vector<uint8_t> signature = {0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x4E, 0x43};
        
        if (fileData.size() >= signature.size()) {
            for (size_t i = 0; i < signature.size(); ++i) {
                if (fileData[i] != signature[i]) {
                    return false;
                }
            }
            return true;
        }
        
        return false;
    }
    catch (...) {
        return false;
    }
}

std::string EncryptionService::getLastError() const {
    return lastError_;
}

} 
