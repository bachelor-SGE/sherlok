#include "encryption_dialog.h"
#include <iostream>

namespace ui {

class EncryptionDialog::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    std::string title_;
    std::string message_;
    std::string password_;
    std::vector<std::string> files_;
    bool isEncryptionMode_ = true;
    bool showWarning_ = false;
    std::string warningText_;
    std::string validationError_;
    bool isVisible_ = false;
};

EncryptionDialog::EncryptionDialog() : pImpl_(std::make_unique<Impl>()) {
    
}

bool EncryptionDialog::show() {
    pImpl_->isVisible_ = true;
    
    std::cout << "=== Диалог шифрования ===" << std::endl;
    std::cout << "Заголовок: " << pImpl_->title_ << std::endl;
    std::cout << "Сообщение: " << pImpl_->message_ << std::endl;
    std::cout << "Режим: " << (pImpl_->isEncryptionMode_ ? "Шифрование" : "Дешифрование") << std::endl;
    
    if (pImpl_->showWarning_ && !pImpl_->warningText_.empty()) {
        std::cout << "ПРЕДУПРЕЖДЕНИЕ: " << pImpl_->warningText_ << std::endl;
    }
    
    if (!pImpl_->files_.empty()) {
        std::cout << "Файлы для обработки:" << std::endl;
        for (const auto& file : pImpl_->files_) {
            std::cout << "  - " << file << std::endl;
        }
    }
    
    if (!pImpl_->validationError_.empty()) {
        std::cout << "Ошибка валидации: " << pImpl_->validationError_ << std::endl;
    }
    
    
    
    std::cout << "Пользователь подтвердил действие" << std::endl;
    return true;
}

void EncryptionDialog::hide() {
    pImpl_->isVisible_ = false;
    std::cout << "Диалог шифрования скрыт" << std::endl;
}

void EncryptionDialog::setTitle(const std::string& title) {
    pImpl_->title_ = title;
}

void EncryptionDialog::setMessage(const std::string& message) {
    pImpl_->message_ = message;
}

void EncryptionDialog::setFiles(const std::vector<std::string>& files) {
    pImpl_->files_ = files;
}

std::string EncryptionDialog::getPassword() const {
    return pImpl_->password_;
}

void EncryptionDialog::setConfirmCallback(std::function<void(const std::string&)> callback) {
    confirmCallback_ = callback;
}

void EncryptionDialog::setCancelCallback(std::function<void()> callback) {
    cancelCallback_ = callback;
}

void EncryptionDialog::showValidationError(const std::string& message) {
    pImpl_->validationError_ = message;
    std::cout << "Показана ошибка валидации: " << message << std::endl;
}

void EncryptionDialog::clearValidationError() {
    pImpl_->validationError_.clear();
    std::cout << "Ошибка валидации очищена" << std::endl;
}

void EncryptionDialog::setEncryptionMode(bool isEncryption) {
    pImpl_->isEncryptionMode_ = isEncryption;
}

void EncryptionDialog::setShowWarning(bool showWarning) {
    pImpl_->showWarning_ = showWarning;
}

void EncryptionDialog::setWarningText(const std::string& warningText) {
    pImpl_->warningText_ = warningText;
}

} 
