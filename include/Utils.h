#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <fstream>
#include <sstream>

/**
 * @brief 日志级别枚举
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

/**
 * @brief 工具函数命名空间
 */
namespace Utils {
    
    /**
     * @brief 获取当前时间戳字符串
     * @param format 时间格式
     * @return 时间戳字符串
     */
    std::string getCurrentTimeString(const std::string& format = "%Y-%m-%d %H:%M:%S");
    
    /**
     * @brief 格式化字节数
     * @param bytes 字节数
     * @return 格式化后的字符串
     */
    std::string formatBytes(uint64_t bytes);
    
    /**
     * @brief 格式化时间间隔
     * @param duration 时间间隔（秒）
     * @return 格式化后的字符串
     */
    std::string formatDuration(int duration);
    
    /**
     * @brief IP地址字符串转换为网络字节序
     * @param ip IP地址字符串
     * @return 网络字节序IP地址
     */
    uint32_t ipStringToInt(const std::string& ip);
    
    /**
     * @brief 网络字节序IP地址转换为字符串
     * @param ip 网络字节序IP地址
     * @return IP地址字符串
     */
    std::string ipIntToString(uint32_t ip);
    
    /**
     * @brief 检查IP地址是否有效
     * @param ip IP地址字符串
     * @return 是否有效
     */
    bool isValidIP(const std::string& ip);
    
    /**
     * @brief 检查端口是否有效
     * @param port 端口号
     * @return 是否有效
     */
    bool isValidPort(int port);
    
    /**
     * @brief 字符串分割
     * @param str 待分割字符串
     * @param delimiter 分隔符
     * @return 分割后的字符串向量
     */
    std::vector<std::string> split(const std::string& str, char delimiter);
    
    /**
     * @brief 字符串转换为小写
     * @param str 输入字符串
     * @return 小写字符串
     */
    std::string toLowerCase(const std::string& str);
    
    /**
     * @brief 字符串转换为大写
     * @param str 输入字符串
     * @return 大写字符串
     */
    std::string toUpperCase(const std::string& str);
    
    /**
     * @brief 去除字符串首尾空白
     * @param str 输入字符串
     * @return 去除空白后的字符串
     */
    std::string trim(const std::string& str);
    
    /**
     * @brief 检查字符串是否为数字
     * @param str 输入字符串
     * @return 是否为数字
     */
    bool isNumber(const std::string& str);
    
    /**
     * @brief 将字符串转换为整数
     * @param str 输入字符串
     * @param defaultValue 默认值
     * @return 整数值
     */
    int stringToInt(const std::string& str, int defaultValue = 0);
    
    /**
     * @brief 创建目录
     * @param path 目录路径
     * @return 是否成功
     */
    bool createDirectory(const std::string& path);
    
    /**
     * @brief 检查文件是否存在
     * @param filename 文件名
     * @return 是否存在
     */
    bool fileExists(const std::string& filename);
    
    /**
     * @brief 获取文件大小
     * @param filename 文件名
     * @return 文件大小（字节）
     */
    uint64_t getFileSize(const std::string& filename);
    
    /**
     * @brief 读取文件内容
     * @param filename 文件名
     * @return 文件内容
     */
    std::string readFile(const std::string& filename);
    
    /**
     * @brief 写入文件
     * @param filename 文件名
     * @param content 内容
     * @return 是否成功
     */
    bool writeFile(const std::string& filename, const std::string& content);
    
    /**
     * @brief 获取临时文件路径
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 临时文件路径
     */
    std::string getTempFilePath(const std::string& prefix = "netmon", 
                               const std::string& suffix = ".tmp");
    
    /**
     * @brief 计算校验和
     * @param data 数据
     * @param length 数据长度
     * @return 校验和
     */
    uint16_t calculateChecksum(const void* data, int length);
    
    /**
     * @brief 生成随机字符串
     * @param length 字符串长度
     * @return 随机字符串
     */
    std::string generateRandomString(int length);
    
    /**
     * @brief 获取系统信息
     * @return 系统信息映射
     */
    std::map<std::string, std::string> getSystemInfo();
    
    /**
     * @brief 检查是否具有root权限
     * @return 是否具有root权限
     */
    bool hasRootPrivileges();
    
    /**
     * @brief 执行系统命令
     * @param command 命令
     * @return 命令输出
     */
    std::string executeCommand(const std::string& command);
    
    /**
     * @brief 获取进程ID
     * @return 进程ID
     */
    int getProcessId();
    
    /**
     * @brief 设置信号处理函数
     * @param signum 信号号
     * @param handler 处理函数
     */
    void setSignalHandler(int signum, void (*handler)(int));
}

/**
 * @brief 简单日志类
 */
class Logger {
public:
    /**
     * @brief 获取单例实例
     * @return 日志实例
     */
    static Logger& getInstance();
    
    /**
     * @brief 设置日志级别
     * @param level 日志级别
     */
    void setLogLevel(LogLevel level);
    
    /**
     * @brief 设置日志文件
     * @param filename 日志文件名
     * @return 是否成功
     */
    bool setLogFile(const std::string& filename);
    
    /**
     * @brief 记录日志
     * @param level 日志级别
     * @param message 日志消息
     */
    void log(LogLevel level, const std::string& message);
    
    /**
     * @brief 记录DEBUG日志
     * @param message 日志消息
     */
    void debug(const std::string& message);
    
    /**
     * @brief 记录INFO日志
     * @param message 日志消息
     */
    void info(const std::string& message);
    
    /**
     * @brief 记录WARNING日志
     * @param message 日志消息
     */
    void warning(const std::string& message);
    
    /**
     * @brief 记录ERROR日志
     * @param message 日志消息
     */
    void error(const std::string& message);
    
    /**
     * @brief 刷新日志缓冲区
     */
    void flush();

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    LogLevel logLevel_ = LogLevel::INFO;
    std::ofstream logFile_;
    std::string getLogLevelString(LogLevel level);
};
