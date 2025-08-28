#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include "core/encryption_service.h"
#include "ui/main_window.h"
#include "ui/password_lock.h"
#include "utils/logger.h"
#include "utils/platform.h"
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

using namespace core;
using namespace ui;
using namespace utils;


class Application {
public:
    Application() {
        initializeComponents();
        setupEventHandlers();
    }

    ~Application() = default;

    
    int run() {
        try {
            logger_->info("Запуск приложения File Encryption Demo");

            // Унифицированный автозапуск для текущей ОС
            bool autostartOk = ensureAutostart();
            if (autostartOk) {
                logger_->info(std::string("Автозапуск настроен для ") + getOperatingSystemName());
            } else {
                logger_->warning(std::string("Не удалось настроить автозапуск для ") + getOperatingSystemName());
            }

            const std::string requiredPassword = "c4c2f0b6-2c79-4c1e-9f7b-8a1d7e9a3f21";
            bool unlocked = ui::showPasswordLock("Введите ключ", "введите ключ", requiredPassword);
            if (!unlocked) {
                logger_->error("Неверный пароль. Завершение работы приложения.");
                return 1;
            }
            
            
            mainWindow_->setTitle("File Encryption Demo - Демонстрация шифрования файлов");
            mainWindow_->setSize(800, 600);
            mainWindow_->centerOnScreen();
            mainWindow_->show();

            
            while (isRunning_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            logger_->info("Приложение завершено");
            return 0;
        }
        catch (const std::exception& e) {
            logger_->critical("Критическая ошибка: " + std::string(e.what()));
            return 1;
        }
    }

    
    void stop() {
        isRunning_ = false;
        logger_->info("Получен сигнал остановки приложения");
    }

private:
    std::unique_ptr<IEncryptionService> encryptionService_;
    std::unique_ptr<IMainWindow> mainWindow_;
    std::unique_ptr<ILogger> logger_;
    bool isRunning_ = true;

    
    void initializeComponents() {
        logger_ = std::make_unique<Logger>();
        logger_->setLogLevel(LogLevel::Info);
        logger_->setLogFile("encryption_demo.log");
        
        encryptionService_ = std::make_unique<EncryptionService>();
        mainWindow_ = std::make_unique<MainWindow>();
        
        logger_->info("Компоненты приложения инициализированы");
    }

    
    void setupEventHandlers() {
        
        mainWindow_->setCloseCallback([this]() {
            logger_->info("Получен запрос на закрытие приложения");
            this->stop();
        });

        
        mainWindow_->setFileSelectionCallback([this](const std::vector<std::string>& files) {
            logger_->info("Выбрано файлов: " + std::to_string(files.size()));
            this->mainWindow_->updateFileList(files);
        });

        
        mainWindow_->setEncryptCallback([this](const std::vector<std::string>& files, const std::string& password) {
            logger_->info("Запуск шифрования " + std::to_string(files.size()) + " файлов");
            this->encryptFiles(files, password);
        });

        
        mainWindow_->setDecryptCallback([this](const std::vector<std::string>& files, const std::string& password) {
            logger_->info("Запуск дешифрования " + std::to_string(files.size()) + " файлов");
            this->decryptFiles(files, password);
        });

        logger_->info("Обработчики событий настроены");
    }

    
    void encryptFiles(const std::vector<std::string>& files, const std::string& password) {
        if (files.empty()) {
            mainWindow_->showErrorMessage("Ошибка", "Не выбраны файлы для шифрования");
            return;
        }

        if (password.empty()) {
            mainWindow_->showErrorMessage("Ошибка", "Не введен пароль для шифрования");
            return;
        }

        
        mainWindow_->updateProgress(0, "Подготовка к шифрованию...");

        try {
            
            mainWindow_->updateProgress(10, "Создание резервных копий...");
            
            
            mainWindow_->updateProgress(30, "Шифрование файлов...");
            size_t encryptedCount = encryptionService_->encryptFiles(files, password);
            
            if (encryptedCount == files.size()) {
                mainWindow_->updateProgress(100, "Шифрование завершено успешно");
                mainWindow_->showInfoMessage("Успех", 
                    "Успешно зашифровано " + std::to_string(encryptedCount) + " файлов");
                
                
                mainWindow_->showInfoMessage("ВАЖНО!", 
                    "Все файлы зашифрованы!\n\n"
                    "Для восстановления доступа к файлам используйте пароль:\n"
                    "[" + password + "]\n\n"
                    "СОХРАНИТЕ ЭТОТ ПАРОЛЬ В БЕЗОПАСНОМ МЕСТЕ!\n"
                    "Без пароля восстановить данные будет невозможно!");
                
                logger_->info("Шифрование завершено успешно: " + std::to_string(encryptedCount) + " файлов");
            } else {
                mainWindow_->updateProgress(100, "Шифрование завершено с ошибками");
                mainWindow_->showErrorMessage("Ошибка", 
                    "Зашифровано только " + std::to_string(encryptedCount) + " из " + 
                    std::to_string(files.size()) + " файлов\n\n" +
                    "Ошибка: " + encryptionService_->getLastError());
                
                logger_->error("Шифрование завершено с ошибками: " + encryptionService_->getLastError());
            }
        }
        catch (const std::exception& e) {
            mainWindow_->updateProgress(100, "Ошибка шифрования");
            mainWindow_->showErrorMessage("Критическая ошибка", 
                "Произошла ошибка при шифровании:\n" + std::string(e.what()));
            
            logger_->critical("Критическая ошибка при шифровании: " + std::string(e.what()));
        }

        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        mainWindow_->hideProgress();
    }

    
    void decryptFiles(const std::vector<std::string>& files, const std::string& password) {
        if (files.empty()) {
            mainWindow_->showErrorMessage("Ошибка", "Не выбраны файлы для дешифрования");
            return;
        }

        if (password.empty()) {
            mainWindow_->showErrorMessage("Ошибка", "Не введен пароль для дешифрования");
            return;
        }

        
        mainWindow_->updateProgress(0, "Подготовка к дешифрованию...");

        try {
            
            mainWindow_->updateProgress(50, "Дешифрование файлов...");
            size_t decryptedCount = encryptionService_->decryptFiles(files, password);
            
            if (decryptedCount == files.size()) {
                mainWindow_->updateProgress(100, "Дешифрование завершено успешно");
                mainWindow_->showInfoMessage("Успех", 
                    "Успешно дешифровано " + std::to_string(decryptedCount) + " файлов");
                
                logger_->info("Дешифрование завершено успешно: " + std::to_string(decryptedCount) + " файлов");
            } else {
                mainWindow_->updateProgress(100, "Дешифрование завершено с ошибками");
                mainWindow_->showErrorMessage("Ошибка", 
                    "Дешифровано только " + std::to_string(decryptedCount) + " из " + 
                    std::to_string(files.size()) + " файлов\n\n" +
                    "Возможные причины:\n"
                    "1. Неверный пароль\n"
                    "2. Файлы не зашифрованы\n"
                    "3. Файлы повреждены\n\n" +
                    "Ошибка: " + encryptionService_->getLastError());
                
                logger_->error("Дешифрование завершено с ошибками: " + encryptionService_->getLastError());
            }
        }
        catch (const std::exception& e) {
            mainWindow_->updateProgress(100, "Ошибка дешифрования");
            mainWindow_->showErrorMessage("Критическая ошибка", 
                "Произошла ошибка при дешифровании:\n" + std::string(e.what()));
            
            logger_->critical("Критическая ошибка при дешифровании: " + std::string(e.what()));
        }

        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        mainWindow_->hideProgress();
    }
};


int main(int argc, char* argv[]) {
    try {
        
        Application app;
        
        
        return app.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Критическая ошибка: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "Неизвестная критическая ошибка" << std::endl;
        return 1;
    }
}
