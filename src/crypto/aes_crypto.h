#pragma once

#include <string>
#include <vector>
#include <memory>

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#else
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif
#endif

namespace crypto {


class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::string& key) = 0;

    
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encryptedData, const std::string& key) = 0;

    
    virtual std::string generateKey(size_t keyLength = 32) = 0;

    
    virtual std::string hashPassword(const std::string& password, const std::string& salt) = 0;

    
    virtual bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) = 0;

    
    virtual std::string getLastError() const = 0;
};


class AESCryptoProvider : public ICryptoProvider {
public:
    AESCryptoProvider();
    ~AESCryptoProvider() override;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::string& key) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encryptedData, const std::string& key) override;
    std::string generateKey(size_t keyLength = 32) override;
    std::string hashPassword(const std::string& password, const std::string& salt) override;
    bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) override;
    std::string getLastError() const override;

private:
    std::string lastError_;
    
    
    std::string generateSalt(size_t length = 16);
    
    
    std::vector<uint8_t> deriveKey(const std::string& password, const std::string& salt, size_t keyLength = 32);
    
    
    std::vector<uint8_t> generateIV(size_t length = 16);
    
    
    std::string toHexString(const std::vector<uint8_t>& data);
    
    
    std::vector<uint8_t> fromHexString(const std::string& hexString);
};

} 
