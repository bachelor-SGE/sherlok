#pragma once

#include <string>
#include <vector>
#include <memory>

namespace core {


class IFileManager {
public:
    virtual ~IFileManager() = default;

    
    virtual std::vector<uint8_t> readFile(const std::string& filePath) = 0;

    
    virtual bool writeFile(const std::string& filePath, const std::vector<uint8_t>& data) = 0;

    
    virtual bool fileExists(const std::string& filePath) const = 0;

    
    virtual int64_t getFileSize(const std::string& filePath) const = 0;

    
    virtual bool createBackup(const std::string& filePath, const std::string& backupPath) = 0;

    
    virtual bool restoreFromBackup(const std::string& backupPath, const std::string& filePath) = 0;

    
    virtual std::vector<std::string> getFilesInDirectory(const std::string& directoryPath, bool recursive = false) = 0;

    
    virtual std::string getLastError() const = 0;
};


class FileManager : public IFileManager {
public:
    FileManager();
    ~FileManager() override = default;

    std::vector<uint8_t> readFile(const std::string& filePath) override;
    bool writeFile(const std::string& filePath, const std::vector<uint8_t>& data) override;
    bool fileExists(const std::string& filePath) const override;
    int64_t getFileSize(const std::string& filePath) const override;
    bool createBackup(const std::string& filePath, const std::string& backupPath) override;
    bool restoreFromBackup(const std::string& backupPath, const std::string& filePath) override;
    std::vector<std::string> getFilesInDirectory(const std::string& directoryPath, bool recursive = false) override;
    std::string getLastError() const override;

private:
    std::string lastError_;
    
    
    bool checkFilePermissions(const std::string& filePath) const;
    
    
    bool ensureDirectoryExists(const std::string& directoryPath) const;
};

} 
