#pragma once

#include <string>
#include <vector>
#include <memory>

namespace utils {


class IFileUtils {
public:
    virtual ~IFileUtils() = default;

    
    virtual bool fileExists(const std::string& filePath) const = 0;

    
    virtual bool directoryExists(const std::string& dirPath) const = 0;

    
    virtual bool createDirectory(const std::string& dirPath, bool createParents = true) const = 0;

    
    virtual bool deleteFile(const std::string& filePath) const = 0;

    
    virtual bool deleteDirectory(const std::string& dirPath, bool recursive = false) const = 0;

    
    virtual bool copyFile(const std::string& sourcePath, const std::string& destPath, bool overwrite = false) const = 0;

    
    virtual bool moveFile(const std::string& sourcePath, const std::string& destPath) const = 0;

    
    virtual int64_t getFileSize(const std::string& filePath) const = 0;

    
    virtual int64_t getFileModificationTime(const std::string& filePath) const = 0;

    
    virtual std::string getFileExtension(const std::string& filePath) const = 0;

    
    virtual std::string getFileName(const std::string& filePath) const = 0;

    
    virtual std::string getDirectoryPath(const std::string& filePath) const = 0;

    
    virtual std::string getAbsolutePath(const std::string& filePath) const = 0;

    
    virtual std::string normalizePath(const std::string& filePath) const = 0;

    
    virtual std::string joinPath(const std::vector<std::string>& parts) const = 0;

    
    virtual std::vector<std::string> getFilesInDirectory(const std::string& dirPath, const std::string& pattern = "*", bool recursive = false) const = 0;

    
    virtual bool checkFilePermissions(const std::string& filePath, bool checkRead = true, bool checkWrite = false) const = 0;
};


class FileUtils : public IFileUtils {
public:
    FileUtils();
    ~FileUtils() override = default;

    bool fileExists(const std::string& filePath) const override;
    bool directoryExists(const std::string& dirPath) const override;
    bool createDirectory(const std::string& dirPath, bool createParents = true) const override;
    bool deleteFile(const std::string& filePath) const override;
    bool deleteDirectory(const std::string& dirPath, bool recursive = false) const override;
    bool copyFile(const std::string& sourcePath, const std::string& destPath, bool overwrite = false) const override;
    bool moveFile(const std::string& sourcePath, const std::string& destPath) const override;
    int64_t getFileSize(const std::string& filePath) const override;
    int64_t getFileModificationTime(const std::string& filePath) const override;
    std::string getFileExtension(const std::string& filePath) const override;
    std::string getFileName(const std::string& filePath) const override;
    std::string getDirectoryPath(const std::string& filePath) const override;
    std::string getAbsolutePath(const std::string& filePath) const override;
    std::string normalizePath(const std::string& filePath) const override;
    std::string joinPath(const std::vector<std::string>& parts) const override;
    std::vector<std::string> getFilesInDirectory(const std::string& dirPath, const std::string& pattern = "*", bool recursive = false) const override;
    bool checkFilePermissions(const std::string& filePath, bool checkRead = true, bool checkWrite = false) const override;

private:
    
    bool isAbsolutePath(const std::string& filePath) const;
    
    
    std::vector<std::string> splitPath(const std::string& filePath) const;
    
    
    bool matchesPattern(const std::string& fileName, const std::string& pattern) const;
};

} 
