#pragma once

#include <string>
#include <vector>
#include <memory>


namespace crypto {
    class ICryptoProvider;
}

namespace core {
    class IFileManager;


class IEncryptionService {
public:
    virtual ~IEncryptionService() = default;

    
    virtual bool encryptFile(const std::string& filePath, const std::string& password) = 0;

    
    virtual bool decryptFile(const std::string& filePath, const std::string& password) = 0;

    
    virtual size_t encryptFiles(const std::vector<std::string>& filePaths, const std::string& password) = 0;

    
    virtual size_t decryptFiles(const std::vector<std::string>& filePaths, const std::string& password) = 0;

    
    virtual bool isFileEncrypted(const std::string& filePath) const = 0;

    
    virtual std::string getLastError() const = 0;
};


class EncryptionService : public IEncryptionService {
public:
    EncryptionService();
    ~EncryptionService() override = default;

    bool encryptFile(const std::string& filePath, const std::string& password) override;
    bool decryptFile(const std::string& filePath, const std::string& password) override;
    size_t encryptFiles(const std::vector<std::string>& filePaths, const std::string& password) override;
    size_t decryptFiles(const std::vector<std::string>& filePaths, const std::string& password) override;
    bool isFileEncrypted(const std::string& filePath) const override;
    std::string getLastError() const override;

private:
    std::string lastError_;
    std::unique_ptr<crypto::ICryptoProvider> cryptoProvider_;
    std::unique_ptr<IFileManager> fileManager_;
};

} 
