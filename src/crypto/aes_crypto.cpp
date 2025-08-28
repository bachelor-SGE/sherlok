#include "aes_crypto.h"
#include <random>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#else
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif
#endif

namespace crypto {

AESCryptoProvider::AESCryptoProvider() {
    
#ifdef USE_OPENSSL
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
}

AESCryptoProvider::~AESCryptoProvider() {
#ifdef USE_OPENSSL
    
    EVP_cleanup();
    ERR_free_strings();
#endif
}

std::vector<uint8_t> AESCryptoProvider::encrypt(const std::vector<uint8_t>& data, const std::string& key) {
    try {
        if (data.empty()) {
            lastError_ = "Нет данных для шифрования";
            return {};
        }

        if (key.empty()) {
            lastError_ = "Ключ шифрования не может быть пустым";
            return {};
        }

#ifdef USE_OPENSSL
        
        auto salt = generateSalt(16);
        auto iv = generateIV(16);
        
        
        auto derivedKey = deriveKey(key, salt, 32);
        
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            lastError_ = "Не удалось создать контекст шифрования OpenSSL";
            return {};
        }
        
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, derivedKey.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            lastError_ = "Не удалось инициализировать шифрование AES-256";
            return {};
        }
        
        
        std::vector<uint8_t> encryptedData;
        encryptedData.resize(data.size() + EVP_MAX_BLOCK_LENGTH);
        
        int outLen = 0;
        int finalLen = 0;
        
        
        if (EVP_EncryptUpdate(ctx, encryptedData.data(), &outLen, data.data(), static_cast<int>(data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            lastError_ = "Ошибка при шифровании данных";
            return {};
        }
        
        
        if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + outLen, &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            lastError_ = "Ошибка при завершении шифрования";
            return {};
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        
        encryptedData.resize(outLen + finalLen);
        
        
        std::vector<uint8_t> result;
        
        
        const std::vector<uint8_t> signature = {0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x4E, 0x43}; 
        result.insert(result.end(), signature.begin(), signature.end());
        
        
        uint64_t originalSize = data.size();
        for (int i = 0; i < 8; ++i) {
            result.push_back(static_cast<uint8_t>((originalSize >> (i * 8)) & 0xFF));
        }
        
        
        result.insert(result.end(), salt.begin(), salt.end());
        
        
        result.insert(result.end(), iv.begin(), iv.end());
        
        
        result.insert(result.end(), encryptedData.begin(), encryptedData.end());
        
        return result;
#else
#ifdef _WIN32
        
        auto salt = generateSalt(16);
        auto iv = generateIV(16);

        
        auto derivedKey = deriveKey(key, salt, 32);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        PBYTE keyObject = nullptr;
        DWORD keyObjectLength = 0;
        DWORD cbData = 0;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status < 0) {
            lastError_ = "Не удалось открыть провайдер AES (CNG)";
            return {};
        }

        
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                   (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (status < 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Не удалось установить режим CBC (CNG)";
            return {};
        }

        
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLength, sizeof(DWORD), &cbData, 0);
        if (status < 0 || keyObjectLength == 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Не удалось получить размер объекта ключа (CNG)";
            return {};
        }

        keyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, keyObjectLength);
        if (!keyObject) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Недостаточно памяти для keyObject (CNG)";
            return {};
        }

        
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectLength,
                                            (PUCHAR)derivedKey.data(), (ULONG)derivedKey.size(), 0);
        if (status < 0) {
            HeapFree(GetProcessHeap(), 0, keyObject);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Не удалось создать симметричный ключ (CNG)";
            return {};
        }

        
        ULONG ciphertextSize = (ULONG)data.size() + 16; 
        std::vector<uint8_t> encryptedData(ciphertextSize);

        
        std::vector<uint8_t> ivMutable(iv.begin(), iv.end());
        ULONG resultSize = 0;
        status = BCryptEncrypt(hKey,
                               (PUCHAR)data.data(), (ULONG)data.size(),
                               nullptr,
                               ivMutable.data(), (ULONG)ivMutable.size(),
                               encryptedData.data(), (ULONG)encryptedData.size(),
                               &resultSize,
                               BCRYPT_BLOCK_PADDING);

        
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status < 0) {
            lastError_ = "Ошибка шифрования (CNG)";
            return {};
        }

        encryptedData.resize(resultSize);

        
        std::vector<uint8_t> result;
        const std::vector<uint8_t> signature = {0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x4E, 0x43};
        result.insert(result.end(), signature.begin(), signature.end());

        uint64_t originalSize = data.size();
        for (int i = 0; i < 8; ++i) {
            result.push_back(static_cast<uint8_t>((originalSize >> (i * 8)) & 0xFF));
        }
        result.insert(result.end(), salt.begin(), salt.end());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), encryptedData.begin(), encryptedData.end());

        return result;
#else
        lastError_ = "Криптопровайдер недоступен: требуется OpenSSL или Windows CNG";
        return {};
#endif
#endif
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при шифровании: " + std::string(e.what());
        return {};
    }
}

std::vector<uint8_t> AESCryptoProvider::decrypt(const std::vector<uint8_t>& encryptedData, const std::string& key) {
    try {
        if (encryptedData.empty()) {
            lastError_ = "Нет данных для дешифрования";
            return {};
        }

        if (key.empty()) {
            lastError_ = "Ключ дешифрования не может быть пустым";
            return {};
        }

        
        if (encryptedData.size() < 49) { 
            lastError_ = "Неверный формат зашифрованных данных";
            return {};
        }

#ifdef USE_OPENSSL
        
        const std::vector<uint8_t> expectedSignature = {0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x4E, 0x43}; 
        for (size_t i = 0; i < expectedSignature.size(); ++i) {
            if (encryptedData[i] != expectedSignature[i]) {
                lastError_ = "Неверная сигнатура зашифрованных данных";
                return {};
            }
        }

        
        uint64_t originalSize = 0;
        for (int i = 0; i < 8; ++i) {
            originalSize |= static_cast<uint64_t>(encryptedData[9 + i]) << (i * 8);
        }

        
        std::vector<uint8_t> salt(encryptedData.begin() + 17, encryptedData.begin() + 33);
        std::vector<uint8_t> iv(encryptedData.begin() + 33, encryptedData.begin() + 49);
        
        
        std::vector<uint8_t> encryptedContent(encryptedData.begin() + 49, encryptedData.end());
        
        
        auto derivedKey = deriveKey(key, std::string(salt.begin(), salt.end()), 32);
        
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            lastError_ = "Не удалось создать контекст дешифрования OpenSSL";
            return {};
        }
        
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, derivedKey.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            lastError_ = "Не удалось инициализировать дешифрование AES-256";
            return {};
        }
        
        
        std::vector<uint8_t> decryptedData;
        decryptedData.resize(encryptedContent.size() + EVP_MAX_BLOCK_LENGTH);
        
        int outLen = 0;
        int finalLen = 0;
        
        
        if (EVP_DecryptUpdate(ctx, decryptedData.data(), &outLen, encryptedContent.data(), static_cast<int>(encryptedContent.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            lastError_ = "Ошибка при дешифровании данных";
            return {};
        }
        
        
        if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + outLen, &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            lastError_ = "Ошибка при завершении дешифрования";
            return {};
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        
        decryptedData.resize(outLen + finalLen);
        
        
        if (decryptedData.size() != originalSize) {
            lastError_ = "Размер расшифрованных данных не соответствует ожидаемому";
            return {};
        }
        
        return decryptedData;
#else
#ifdef _WIN32
        
        const std::vector<uint8_t> expectedSignature = {0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x4E, 0x43};
        for (size_t i = 0; i < expectedSignature.size(); ++i) {
            if (encryptedData[i] != expectedSignature[i]) {
                lastError_ = "Неверная сигнатура зашифрованных данных";
                return {};
            }
        }

        uint64_t originalSize = 0;
        for (int i = 0; i < 8; ++i) {
            originalSize |= static_cast<uint64_t>(encryptedData[9 + i]) << (i * 8);
        }

        std::vector<uint8_t> salt(encryptedData.begin() + 17, encryptedData.begin() + 33);
        std::vector<uint8_t> iv(encryptedData.begin() + 33, encryptedData.begin() + 49);
        std::vector<uint8_t> encryptedContent(encryptedData.begin() + 49, encryptedData.end());

        
        auto derivedKey = deriveKey(key, std::string(salt.begin(), salt.end()), 32);

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        PBYTE keyObject = nullptr;
        DWORD keyObjectLength = 0;
        DWORD cbData = 0;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (status < 0) {
            lastError_ = "Не удалось открыть провайдер AES (CNG)";
            return {};
        }

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                   (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (status < 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Не удалось установить режим CBC (CNG)";
            return {};
        }

        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLength, sizeof(DWORD), &cbData, 0);
        if (status < 0 || keyObjectLength == 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Не удалось получить размер объекта ключа (CNG)";
            return {};
        }

        keyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, keyObjectLength);
        if (!keyObject) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Недостаточно памяти для keyObject (CNG)";
            return {};
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectLength,
                                            (PUCHAR)derivedKey.data(), (ULONG)derivedKey.size(), 0);
        if (status < 0) {
            HeapFree(GetProcessHeap(), 0, keyObject);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            lastError_ = "Не удалось создать симметричный ключ (CNG)";
            return {};
        }

        
        std::vector<uint8_t> decryptedData(encryptedContent.size());

        std::vector<uint8_t> ivMutable(iv.begin(), iv.end());
        ULONG resultSize = 0;
        status = BCryptDecrypt(hKey,
                               (PUCHAR)encryptedContent.data(), (ULONG)encryptedContent.size(),
                               nullptr,
                               ivMutable.data(), (ULONG)ivMutable.size(),
                               decryptedData.data(), (ULONG)decryptedData.size(),
                               &resultSize,
                               BCRYPT_BLOCK_PADDING);

        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, keyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status < 0) {
            lastError_ = "Ошибка дешифрования (CNG)";
            return {};
        }

        decryptedData.resize(resultSize);
        if (decryptedData.size() != originalSize) {
            lastError_ = "Размер расшифрованных данных не соответствует ожидаемому";
            return {};
        }

        return decryptedData;
#else
        lastError_ = "Криптопровайдер недоступен: требуется OpenSSL или Windows CNG";
        return {};
#endif
#endif
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при дешифровании: " + std::string(e.what());
        return {};
    }
}

std::string AESCryptoProvider::generateKey(size_t keyLength) {
    try {
#ifdef USE_OPENSSL
        std::vector<uint8_t> key(keyLength);
        if (RAND_bytes(key.data(), static_cast<int>(keyLength)) != 1) {
            lastError_ = "Ошибка при генерации криптографически стойкого ключа";
            return "";
        }
        return std::string(key.begin(), key.end());
#else
#ifdef _WIN32
        std::vector<uint8_t> keyBytes(keyLength);
        NTSTATUS status = BCryptGenRandom(nullptr, keyBytes.data(), (ULONG)keyBytes.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            lastError_ = "Ошибка при генерации ключа (CNG)";
            return "";
        }
        return std::string(keyBytes.begin(), keyBytes.end());
#else
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(33, 126);
        std::string key;
        key.reserve(keyLength);
        for (size_t i = 0; i < keyLength; ++i) {
            key += static_cast<char>(dis(gen));
        }
        return key;
#endif
#endif
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при генерации ключа: " + std::string(e.what());
        return "";
    }
}

std::string AESCryptoProvider::hashPassword(const std::string& password, const std::string& salt) {
    try {
        if (password.empty()) {
            lastError_ = "Пароль не может быть пустым";
            return "";
        }

#ifdef USE_OPENSSL
        
        std::vector<uint8_t> hash(32); 
        
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                               reinterpret_cast<const unsigned char*>(salt.c_str()), 
                               static_cast<int>(salt.length()),
                               10000, 
                               EVP_sha256(),
                               static_cast<int>(hash.size()),
                               hash.data()) != 1) {
            lastError_ = "Ошибка при хешировании пароля с PBKDF2";
            return "";
        }
        
        return toHexString(hash);
#else
#ifdef _WIN32
        
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status < 0) {
            lastError_ = "Не удалось открыть провайдер SHA256 (CNG)";
            return "";
        }

        std::vector<uint8_t> out(32);
        status = BCryptDeriveKeyPBKDF2(hAlg,
                                       (PUCHAR)password.data(), (ULONG)password.size(),
                                       (PUCHAR)salt.data(), (ULONG)salt.size(),
                                       10000,
                                       out.data(), (ULONG)out.size(), 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status < 0) {
            lastError_ = "Не удалось выполнить PBKDF2 (CNG)";
            return "";
        }
        return toHexString(out);
#else
        
        std::string combined = password + salt;
        uint32_t h = 0x811C9DC5;
        for (char c : combined) {
            h ^= static_cast<uint32_t>(c);
            h *= 0x01000193;
        }
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(8) << h;
        return ss.str();
#endif
#endif
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при хешировании пароля: " + std::string(e.what());
        return "";
    }
}

bool AESCryptoProvider::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    try {
        auto computedHash = hashPassword(password, salt);
        return computedHash == hash;
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при проверке пароля: " + std::string(e.what());
        return false;
    }
}

std::string AESCryptoProvider::getLastError() const {
    return lastError_;
}

std::string AESCryptoProvider::generateSalt(size_t length) {
    try {
#ifdef USE_OPENSSL
        std::vector<uint8_t> salt(length);
        if (RAND_bytes(salt.data(), static_cast<int>(length)) != 1) {
            lastError_ = "Ошибка при генерации криптографически стойкой соли";
            return "";
        }
        return std::string(salt.begin(), salt.end());
#else
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        std::string salt;
        salt.reserve(length);

        for (size_t i = 0; i < length; ++i) {
            salt += static_cast<char>(dis(gen));
        }

        return salt;
#endif
    }
    catch (const std::exception& e) {
        lastError_ = "Исключение при генерации соли: " + std::string(e.what());
        return "";
    }
}

std::vector<uint8_t> AESCryptoProvider::deriveKey(const std::string& password, const std::string& salt, size_t keyLength) {
#ifdef USE_OPENSSL
    std::vector<uint8_t> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                           reinterpret_cast<const unsigned char*>(salt.c_str()), 
                           static_cast<int>(salt.length()),
                           10000, 
                           EVP_sha256(),
                           static_cast<int>(keyLength),
                           key.data()) != 1) {
        throw std::runtime_error("Ошибка при выводе ключа с PBKDF2");
    }
    
    return key;
#else
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) {
        throw std::runtime_error("Не удалось открыть провайдер SHA256 (CNG)");
    }
    std::vector<uint8_t> key(keyLength);
    status = BCryptDeriveKeyPBKDF2(hAlg,
                                   (PUCHAR)password.data(), (ULONG)password.size(),
                                   (PUCHAR)salt.data(), (ULONG)salt.size(),
                                   10000,
                                   key.data(), (ULONG)key.size(), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (status < 0) {
        throw std::runtime_error("Ошибка при выводе ключа PBKDF2 (CNG)");
    }
    return key;
#else
    std::vector<uint8_t> key;
    key.reserve(keyLength);
    for (size_t i = 0; i < keyLength; ++i) {
        key.push_back(static_cast<uint8_t>(password[i % password.length()] ^ salt[i % salt.length()]));
    }
    return key;
#endif
#endif
}

std::vector<uint8_t> AESCryptoProvider::generateIV(size_t length) {
#ifdef USE_OPENSSL
    std::vector<uint8_t> iv(length);
    if (RAND_bytes(iv.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Ошибка при генерации IV");
    }
    return iv;
#else
#ifdef _WIN32
    std::vector<uint8_t> iv(length);
    NTSTATUS status = BCryptGenRandom(nullptr, iv.data(), (ULONG)iv.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        throw std::runtime_error("Ошибка при генерации IV (CNG)");
    }
    return iv;
#else
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::vector<uint8_t> iv;
    iv.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        iv.push_back(static_cast<uint8_t>(dis(gen)));
    }
    return iv;
#endif
#endif
}

std::string AESCryptoProvider::toHexString(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

std::vector<uint8_t> AESCryptoProvider::fromHexString(const std::string& hexString) {
    std::vector<uint8_t> result;
    
    if (hexString.length() % 2 != 0) {
        throw std::invalid_argument("Неверная длина hex строки");
    }
    
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        result.push_back(byte);
    }
    
    return result;
}

} 
