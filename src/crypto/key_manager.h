#pragma once

#include <string>
#include <vector>
#include <memory>

namespace crypto {


class IKeyManager {
public:
    virtual ~IKeyManager() = default;

    
    virtual std::string generateKey(size_t keyLength = 32) = 0;

    
    virtual bool storeKey(const std::string& keyId, const std::string& key, const std::string& password) = 0;

    
    virtual std::string retrieveKey(const std::string& keyId, const std::string& password) = 0;

    
    virtual bool deleteKey(const std::string& keyId, const std::string& password) = 0;

    
    virtual bool keyExists(const std::string& keyId) const = 0;

    
    virtual std::vector<std::string> listKeys() const = 0;

    
    virtual std::string exportKey(const std::string& keyId, const std::string& password) = 0;

    
    virtual bool importKey(const std::string& keyId, const std::string& exportedKey, const std::string& password) = 0;

    
    virtual std::string getLastError() const = 0;
};


class KeyManager : public IKeyManager {
public:
    KeyManager();
    ~KeyManager() override = default;

    std::string generateKey(size_t keyLength = 32) override;
    bool storeKey(const std::string& keyId, const std::string& key, const std::string& password) override;
    std::string retrieveKey(const std::string& keyId, const std::string& password) override;
    bool deleteKey(const std::string& keyId, const std::string& password) override;
    bool keyExists(const std::string& keyId) const override;
    std::vector<std::string> listKeys() const override;
    std::string exportKey(const std::string& keyId, const std::string& password) override;
    bool importKey(const std::string& keyId, const std::string& exportedKey, const std::string& password) override;
    std::string getLastError() const override;

private:
    mutable std::string lastError_;
    std::string storagePath_;
    
    
    std::vector<uint8_t> encryptForStorage(const std::vector<uint8_t>& data, const std::string& password);
    
    
    std::vector<uint8_t> decryptFromStorage(const std::vector<uint8_t>& encryptedData, const std::string& password);
    
    
    std::string getKeyFilePath(const std::string& keyId) const;
    
    
    bool ensureStorageDirectoryExists() const;
};

} 
