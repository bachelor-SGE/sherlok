#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace ui {


class IEncryptionDialog {
public:
    virtual ~IEncryptionDialog() = default;

    
    virtual bool show() = 0;

    
    virtual void hide() = 0;

    
    virtual void setTitle(const std::string& title) = 0;

    
    virtual void setMessage(const std::string& message) = 0;

    
    virtual void setFiles(const std::vector<std::string>& files) = 0;

    
    virtual std::string getPassword() const = 0;

    
    virtual void setConfirmCallback(std::function<void(const std::string&)> callback) = 0;

    
    virtual void setCancelCallback(std::function<void()> callback) = 0;

    
    virtual void showValidationError(const std::string& message) = 0;

    
    virtual void clearValidationError() = 0;

    
    virtual void setEncryptionMode(bool isEncryption) = 0;

    
    virtual void setShowWarning(bool showWarning) = 0;

    
    virtual void setWarningText(const std::string& warningText) = 0;
};


class EncryptionDialog : public IEncryptionDialog {
public:
    EncryptionDialog();
    ~EncryptionDialog() override = default;

    bool show() override;
    void hide() override;
    void setTitle(const std::string& title) override;
    void setMessage(const std::string& message) override;
    void setFiles(const std::vector<std::string>& files) override;
    std::string getPassword() const override;
    void setConfirmCallback(std::function<void(const std::string&)> callback) override;
    void setCancelCallback(std::function<void()> callback) override;
    void showValidationError(const std::string& message) override;
    void clearValidationError() override;
    void setEncryptionMode(bool isEncryption) override;
    void setShowWarning(bool showWarning) override;
    void setWarningText(const std::string& warningText) override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    
    std::function<void(const std::string&)> confirmCallback_;
    std::function<void()> cancelCallback_;
    
    
    std::string title_;
    std::string message_;
    std::string password_;
    std::vector<std::string> files_;
    bool isEncryptionMode_;
    bool showWarning_;
    std::string warningText_;
    std::string validationError_;
};

} 
