#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "crypto/aes_crypto.h"

int main() {
    std::cout << "File Encryption Demo - Реальное AES-256-CBC шифрование" << std::endl;

    const std::string plainPath = "test.txt";
    const std::string encPath = "test.encrypted";
    const std::string decPath = "test.decrypted.txt";
    const std::string password = "demo123";

    
    const std::string content =
        "Это тестовый файл для демонстрации реального AES-256-CBC шифрования.\n"
        "Шифрование выполняется через системный провайдер (Windows CNG) или OpenSSL, если доступен.\n";

    
    {
        std::ofstream out(plainPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            std::cerr << "Не удалось записать файл: " << plainPath << std::endl;
            return 1;
        }
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    crypto::AESCryptoProvider crypto;

    
    std::vector<uint8_t> data(content.begin(), content.end());
    auto encrypted = crypto.encrypt(data, password);
    if (encrypted.empty()) {
        std::cerr << "Ошибка шифрования: " << crypto.getLastError() << std::endl;
        return 1;
    }

    
    {
        std::ofstream out(encPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            std::cerr << "Не удалось записать зашифрованный файл: " << encPath << std::endl;
            return 1;
        }
        out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    }

    
    auto decrypted = crypto.decrypt(encrypted, password);
    if (decrypted.empty()) {
        std::cerr << "Ошибка дешифрования: " << crypto.getLastError() << std::endl;
        return 1;
    }

    
    if (decrypted.size() != data.size() || !std::equal(decrypted.begin(), decrypted.end(), data.begin())) {
        std::cerr << "Целостность нарушена: расшифрованные данные не совпадают с исходными" << std::endl;
        return 1;
    }

    
    {
        std::ofstream out(decPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            std::cerr << "Не удалось записать файл: " << decPath << std::endl;
            return 1;
        }
        out.write(reinterpret_cast<const char*>(decrypted.data()), static_cast<std::streamsize>(decrypted.size()));
    }

    std::cout << "Шифрование/дешифрование выполнены успешно." << std::endl;
    std::cout << "Созданы файлы: \n  - " << plainPath << "\n  - " << encPath << "\n  - " << decPath << std::endl;
    return 0;
}
