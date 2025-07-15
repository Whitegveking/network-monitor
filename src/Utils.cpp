#include "Utils.h"
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <random>
#include <sys/utsname.h>
#include <cstring>
#include <csignal>

namespace Utils {

std::string getCurrentTimeString(const std::string& format) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), format.c_str());
    return ss.str();
}

std::string formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string formatDuration(int duration) {
    int hours = duration / 3600;
    int minutes = (duration % 3600) / 60;
    int seconds = duration % 60;
    
    std::ostringstream oss;
    if (hours > 0) {
        oss << hours << "h ";
    }
    if (minutes > 0) {
        oss << minutes << "m ";
    }
    oss << seconds << "s";
    
    return oss.str();
}

uint32_t ipStringToInt(const std::string& ip) {
    struct in_addr addr;
    if (inet_aton(ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

std::string ipIntToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return std::string(inet_ntoa(addr));
}

bool isValidIP(const std::string& ip) {
    struct in_addr addr;
    return inet_aton(ip.c_str(), &addr) == 1;
}

bool isValidPort(int port) {
    return port >= 1 && port <= 65535;
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string toLowerCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string toUpperCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) {
        return "";
    }
    
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

bool isNumber(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    
    for (char c : str) {
        if (!std::isdigit(c)) {
            return false;
        }
    }
    
    return true;
}

int stringToInt(const std::string& str, int defaultValue) {
    try {
        return std::stoi(str);
    } catch (const std::exception&) {
        return defaultValue;
    }
}

bool createDirectory(const std::string& path) {
    return mkdir(path.c_str(), 0755) == 0;
}

bool fileExists(const std::string& filename) {
    struct stat buffer;
    return stat(filename.c_str(), &buffer) == 0;
}

uint64_t getFileSize(const std::string& filename) {
    struct stat buffer;
    if (stat(filename.c_str(), &buffer) == 0) {
        return static_cast<uint64_t>(buffer.st_size);
    }
    return 0;
}

std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return "";
    }
    
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

bool writeFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return true;
}

std::string getTempFilePath(const std::string& prefix, const std::string& suffix) {
    std::string tempDir = "/tmp/";
    std::string randomStr = generateRandomString(8);
    return tempDir + prefix + "_" + randomStr + suffix;
}

uint16_t calculateChecksum(const void* data, int length) {
    const uint16_t* ptr = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    
    // 计算16位字的和
    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    
    // 处理奇数字节
    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }
    
    // 处理进位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return static_cast<uint16_t>(~sum);
}

std::string generateRandomString(int length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.length() - 1);
    
    std::string result;
    result.reserve(length);
    
    for (int i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    
    return result;
}

std::map<std::string, std::string> getSystemInfo() {
    std::map<std::string, std::string> info;
    
    struct utsname uts;
    if (uname(&uts) == 0) {
        info["system"] = uts.sysname;
        info["release"] = uts.release;
        info["version"] = uts.version;
        info["machine"] = uts.machine;
        info["hostname"] = uts.nodename;
    }
    
    return info;
}

bool hasRootPrivileges() {
    return geteuid() == 0;
}

std::string executeCommand(const std::string& command) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "";
    }
    
    std::string result;
    char buffer[256];
    
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    pclose(pipe);
    return result;
}

int getProcessId() {
    return getpid();
}

void setSignalHandler(int signum, void (*handler)(int)) {
    signal(signum, handler);
}

} // namespace Utils

// Logger 实现
Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::setLogLevel(LogLevel level) {
    logLevel_ = level;
}

bool Logger::setLogFile(const std::string& filename) {
    logFile_.open(filename, std::ios::app);
    return logFile_.is_open();
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < logLevel_) {
        return;
    }
    
    std::string timestamp = Utils::getCurrentTimeString();
    std::string levelStr = getLogLevelString(level);
    std::string logMessage = "[" + timestamp + "] [" + levelStr + "] " + message;
    
    // 输出到控制台
    std::cout << logMessage << std::endl;
    
    // 输出到文件
    if (logFile_.is_open()) {
        logFile_ << logMessage << std::endl;
        logFile_.flush();
    }
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::flush() {
    if (logFile_.is_open()) {
        logFile_.flush();
    }
}

std::string Logger::getLogLevelString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR:   return "ERROR";
        default:                return "UNKNOWN";
    }
}
