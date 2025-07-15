#pragma once

#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>
#include <future>

/**
 * @brief 端口扫描结果
 */
struct PortScanResult {
    int port;                   // 端口号
    bool isOpen;                // 是否开放
    std::string service;        // 服务名称
    std::string version;        // 版本信息
    int responseTime;           // 响应时间（毫秒）
};

/**
 * @brief 端口扫描类
 * 
 * 提供TCP和UDP端口扫描功能
 */
class PortScanner {
public:
    /**
     * @brief 扫描类型枚举
     */
    enum class ScanType {
        TCP_CONNECT,    // TCP连接扫描
        TCP_SYN,        // TCP SYN扫描
        UDP,            // UDP扫描
        TCP_FIN,        // TCP FIN扫描
        TCP_NULL,       // TCP NULL扫描
        TCP_XMAS        // TCP XMAS扫描
    };
    
    /**
     * @brief 构造函数
     */
    PortScanner();
    
    /**
     * @brief 析构函数
     */
    ~PortScanner();
    
    /**
     * @brief 扫描单个端口
     * @param host 目标主机
     * @param port 端口号
     * @param type 扫描类型
     * @param timeout 超时时间（毫秒）
     * @return 扫描结果
     */
    PortScanResult scanPort(const std::string& host, int port, 
                           ScanType type = ScanType::TCP_CONNECT, 
                           int timeout = 1000);
    
    /**
     * @brief 扫描端口范围
     * @param host 目标主机
     * @param startPort 起始端口
     * @param endPort 结束端口
     * @param type 扫描类型
     * @param threads 线程数
     * @return 扫描结果列表
     */
    std::vector<PortScanResult> scanPortRange(const std::string& host, 
                                             int startPort, int endPort,
                                             ScanType type = ScanType::TCP_CONNECT,
                                             int threads = 50);
    
    /**
     * @brief 扫描常见端口
     * @param host 目标主机
     * @param type 扫描类型
     * @return 扫描结果列表
     */
    std::vector<PortScanResult> scanCommonPorts(const std::string& host,
                                               ScanType type = ScanType::TCP_CONNECT);
    
    /**
     * @brief 停止扫描
     */
    void stopScan();
    
    /**
     * @brief 检查是否正在扫描
     * @return 扫描状态
     */
    bool isScanning() const { return scanning_; }
    
    /**
     * @brief 获取扫描进度
     * @return 进度百分比
     */
    double getProgress() const;
    
    /**
     * @brief 设置扫描选项
     * @param delayMs 扫描延迟（毫秒）
     * @param maxRetries 最大重试次数
     */
    void setScanOptions(int delayMs = 0, int maxRetries = 1);
    
    /**
     * @brief 获取服务名称
     * @param port 端口号
     * @param protocol 协议类型
     * @return 服务名称
     */
    static std::string getServiceName(int port, const std::string& protocol = "tcp");
    
    /**
     * @brief 获取常见端口列表
     * @return 端口列表
     */
    static std::vector<int> getCommonPorts();

private:
    std::atomic<bool> scanning_;        // 扫描状态
    std::atomic<int> totalPorts_;       // 总端口数
    std::atomic<int> scannedPorts_;     // 已扫描端口数
    
    // 扫描选项
    int scanDelay_;                     // 扫描延迟
    int maxRetries_;                    // 最大重试次数
    
    // 线程同步
    mutable std::mutex resultsMutex_;
    std::vector<std::future<PortScanResult>> scanFutures_;
    
    // 常见端口映射
    static std::map<int, std::string> commonServices_;
    
    /**
     * @brief TCP连接扫描
     * @param host 目标主机
     * @param port 端口号
     * @param timeout 超时时间
     * @return 扫描结果
     */
    PortScanResult tcpConnectScan(const std::string& host, int port, int timeout);
    
    /**
     * @brief TCP SYN扫描
     * @param host 目标主机
     * @param port 端口号
     * @param timeout 超时时间
     * @return 扫描结果
     */
    PortScanResult tcpSynScan(const std::string& host, int port, int timeout);
    
    /**
     * @brief UDP扫描
     * @param host 目标主机
     * @param port 端口号
     * @param timeout 超时时间
     * @return 扫描结果
     */
    PortScanResult udpScan(const std::string& host, int port, int timeout);
    
    /**
     * @brief 检测服务版本
     * @param host 目标主机
     * @param port 端口号
     * @return 版本信息
     */
    std::string detectServiceVersion(const std::string& host, int port);
    
    /**
     * @brief 解析主机名到IP地址
     * @param hostname 主机名
     * @return IP地址
     */
    std::string resolveHostname(const std::string& hostname);
    
    /**
     * @brief 创建原始套接字
     * @return 套接字描述符
     */
    int createRawSocket();
    
    /**
     * @brief 发送原始数据包
     * @param sockfd 套接字描述符
     * @param packet 数据包
     * @param size 数据包大小
     * @param dest 目标地址
     * @return 是否成功
     */
    bool sendRawPacket(int sockfd, const void* packet, size_t size, 
                      const std::string& dest, int port);
    
    /**
     * @brief 等待响应
     * @param sockfd 套接字描述符
     * @param timeout 超时时间
     * @return 是否收到响应
     */
    bool waitForResponse(int sockfd, int timeout);
    
    /**
     * @brief 初始化常见服务映射
     */
    static void initializeServiceMap();
};
