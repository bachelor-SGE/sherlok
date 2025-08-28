#pragma once

#include <string>
#include <memory>

namespace utils {


enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};


class ILogger {
public:
    virtual ~ILogger() = default;

    
    virtual void log(LogLevel level, const std::string& message) = 0;

    
    virtual void debug(const std::string& message) = 0;

    
    virtual void info(const std::string& message) = 0;

    
    virtual void warning(const std::string& message) = 0;

    
    virtual void error(const std::string& message) = 0;

    
    virtual void critical(const std::string& message) = 0;

    
    virtual void setLogLevel(LogLevel level) = 0;

    
    virtual LogLevel getLogLevel() const = 0;

    
    virtual void setLogFile(const std::string& filePath) = 0;

    
    virtual std::string getLogFile() const = 0;

    
    virtual void clear() = 0;
};


class Logger : public ILogger {
public:
    Logger();
    ~Logger() override = default;

    void log(LogLevel level, const std::string& message) override;
    void debug(const std::string& message) override;
    void info(const std::string& message) override;
    void warning(const std::string& message) override;
    void error(const std::string& message) override;
    void critical(const std::string& message) override;
    void setLogLevel(LogLevel level) override;
    LogLevel getLogLevel() const override;
    void setLogFile(const std::string& filePath) override;
    std::string getLogFile() const override;
    void clear() override;

private:
    LogLevel currentLogLevel_;
    std::string logFilePath_;
    
    
    std::string formatMessage(LogLevel level, const std::string& message) const;
    
    
    std::string getLevelString(LogLevel level) const;
    
    
    std::string getCurrentTime() const;
    
    
    void writeToFile(const std::string& message) const;
};

} 
