#include "logger.h"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>

namespace utils {

Logger::Logger() : currentLogLevel_(LogLevel::Info) {
    
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < currentLogLevel_) {
        return;
    }

    std::string formattedMessage = formatMessage(level, message);
    
    
    if (level >= LogLevel::Warning) {
        std::cerr << formattedMessage << std::endl;
    } else {
        std::cout << formattedMessage << std::endl;
    }
    
    
    if (!logFilePath_.empty()) {
        writeToFile(formattedMessage);
    }
}

void Logger::debug(const std::string& message) {
    log(LogLevel::Debug, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::Info, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::Warning, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::Error, message);
}

void Logger::critical(const std::string& message) {
    log(LogLevel::Critical, message);
}

void Logger::setLogLevel(LogLevel level) {
    currentLogLevel_ = level;
}

LogLevel Logger::getLogLevel() const {
    return currentLogLevel_;
}

void Logger::setLogFile(const std::string& filePath) {
    logFilePath_ = filePath;
    
    
    try {
        std::filesystem::path path(filePath);
        auto parentPath = path.parent_path();
        
        if (!parentPath.empty() && !std::filesystem::exists(parentPath)) {
            std::filesystem::create_directories(parentPath);
        }
    }
    catch (...) {
        
    }
}

std::string Logger::getLogFile() const {
    return logFilePath_;
}

void Logger::clear() {
    if (!logFilePath_.empty()) {
        try {
            std::ofstream file(logFilePath_, std::ios::trunc);
            if (file.is_open()) {
                file.close();
            }
        }
        catch (...) {
            
        }
    }
}

std::string Logger::formatMessage(LogLevel level, const std::string& message) const {
    std::stringstream ss;
    
    
    ss << "[" << getCurrentTime() << "] ";
    
    
    ss << "[" << getLevelString(level) << "] ";
    
    
    ss << message;
    
    return ss.str();
}

std::string Logger::getLevelString(LogLevel level) const {
    switch (level) {
        case LogLevel::Debug:    return "DEBUG";
        case LogLevel::Info:     return "INFO";
        case LogLevel::Warning:  return "WARNING";
        case LogLevel::Error:    return "ERROR";
        case LogLevel::Critical: return "CRITICAL";
        default:                return "UNKNOWN";
    }
}

std::string Logger::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    return ss.str();
}

void Logger::writeToFile(const std::string& message) const {
    try {
        std::ofstream file(logFilePath_, std::ios::app);
        if (file.is_open()) {
            file << message << std::endl;
            file.close();
        }
    }
    catch (...) {
        
    }
}

} 
