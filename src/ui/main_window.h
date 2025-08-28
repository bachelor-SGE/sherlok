#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace ui {


class IMainWindow {
public:
    virtual ~IMainWindow() = default;

    
    virtual void show() = 0;

    
    virtual void hide() = 0;

    
    virtual void setTitle(const std::string& title) = 0;

    
    virtual void setSize(int width, int height) = 0;

    
    virtual void setPosition(int x, int y) = 0;

    
    virtual void centerOnScreen() = 0;

    
    virtual void setCloseCallback(std::function<void()> callback) = 0;

    
    virtual void setFileSelectionCallback(std::function<void(const std::vector<std::string>&)> callback) = 0;

    
    virtual void setEncryptCallback(std::function<void(const std::vector<std::string>&, const std::string&)> callback) = 0;

    
    virtual void setDecryptCallback(std::function<void(const std::vector<std::string>&, const std::string&)> callback) = 0;

    
    virtual std::vector<std::string> showFileDialog(const std::string& title, const std::string& filter, bool multiSelect = true) = 0;

    
    virtual std::string showPasswordDialog(const std::string& title, const std::string& message) = 0;

    
    virtual void showInfoMessage(const std::string& title, const std::string& message) = 0;

    
    virtual void showErrorMessage(const std::string& title, const std::string& message) = 0;

    
    virtual bool showConfirmDialog(const std::string& title, const std::string& message) = 0;

    
    virtual void updateProgress(int value, const std::string& message) = 0;

    
    virtual void hideProgress() = 0;

    
    virtual void updateFileList(const std::vector<std::string>& files) = 0;

    
    virtual void clearFileList() = 0;
};


class MainWindow : public IMainWindow {
public:
    MainWindow();
    ~MainWindow() override;

    void show() override;
    void hide() override;
    void setTitle(const std::string& title) override;
    void setSize(int width, int height) override;
    void setPosition(int x, int y) override;
    void centerOnScreen() override;
    void setCloseCallback(std::function<void()> callback) override;
    void setFileSelectionCallback(std::function<void(const std::vector<std::string>&)> callback) override;
    void setEncryptCallback(std::function<void(const std::vector<std::string>&, const std::string&)> callback) override;
    void setDecryptCallback(std::function<void(const std::vector<std::string>&, const std::string&)> callback) override;
    std::vector<std::string> showFileDialog(const std::string& title, const std::string& filter, bool multiSelect = true) override;
    std::string showPasswordDialog(const std::string& title, const std::string& message) override;
    void showInfoMessage(const std::string& title, const std::string& message) override;
    void showErrorMessage(const std::string& title, const std::string& message) override;
    bool showConfirmDialog(const std::string& title, const std::string& message) override;
    void updateProgress(int value, const std::string& message) override;
    void hideProgress() override;
    void updateFileList(const std::vector<std::string>& files) override;
    void clearFileList() override;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    
    std::function<void()> closeCallback_;
    std::function<void(const std::vector<std::string>&)> fileSelectionCallback_;
    std::function<void(const std::vector<std::string>&, const std::string&)> encryptCallback_;
    std::function<void(const std::vector<std::string>&, const std::string&)> decryptCallback_;
};

} 
