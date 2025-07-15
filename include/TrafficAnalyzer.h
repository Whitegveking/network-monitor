#pragma once

#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include "PacketCapture.h"

/**
 * @brief 流量统计信息
 */
struct TrafficStats {
    uint64_t totalPackets = 0;          // 总包数
    uint64_t totalBytes = 0;            // 总字节数
    uint64_t tcpPackets = 0;            // TCP包数
    uint64_t udpPackets = 0;            // UDP包数
    uint64_t icmpPackets = 0;           // ICMP包数
    uint64_t httpPackets = 0;           // HTTP包数
    uint64_t httpsPackets = 0;          // HTTPS包数
    uint64_t dnsPackets = 0;            // DNS包数
    uint64_t sipPackets = 0;            // SIP包数
    double avgPacketSize = 0.0;         // 平均包大小
    double packetsPerSecond = 0.0;      // 每秒包数
    double bytesPerSecond = 0.0;        // 每秒字节数
};

/**
 * @brief 连接信息
 */
struct ConnectionInfo {
    std::string srcIP;                  // 源IP
    std::string dstIP;                  // 目标IP
    uint16_t srcPort;                   // 源端口
    uint16_t dstPort;                   // 目标端口
    std::string protocol;               // 协议
    uint64_t packets = 0;               // 包数
    uint64_t bytes = 0;                 // 字节数
    std::chrono::steady_clock::time_point lastSeen;  // 最后看到时间
};

/**
 * @brief 主机信息
 */
struct HostInfo {
    std::string ipAddress;              // IP地址
    std::string hostname;               // 主机名
    uint64_t totalPackets = 0;          // 总包数
    uint64_t totalBytes = 0;            // 总字节数
    std::vector<int> activePorts;       // 活跃端口
    std::chrono::steady_clock::time_point firstSeen;  // 首次看到时间
    std::chrono::steady_clock::time_point lastSeen;   // 最后看到时间
};

/**
 * @brief 流量分析器类
 * 
 * 负责分析网络流量，提供统计信息和异常检测
 */
class TrafficAnalyzer {
public:
    /**
     * @brief 构造函数
     */
    TrafficAnalyzer();
    
    /**
     * @brief 析构函数
     */
    ~TrafficAnalyzer();
    
    /**
     * @brief 开始分析
     * @param interface 网络接口
     * @return 是否成功
     */
    bool startAnalysis(const std::string& interface);
    
    /**
     * @brief 停止分析
     */
    void stopAnalysis();
    
    /**
     * @brief 处理数据包
     * @param packet 数据包信息
     */
    void processPacket(const PacketInfo& packet);
    
    /**
     * @brief 获取流量统计
     * @return 统计信息
     */
    TrafficStats getTrafficStats() const;
    
    /**
     * @brief 获取连接列表
     * @return 连接信息列表
     */
    std::vector<ConnectionInfo> getConnections() const;
    
    /**
     * @brief 获取主机列表
     * @return 主机信息列表
     */
    std::vector<HostInfo> getHosts() const;
    
    /**
     * @brief 获取协议分布
     * @return 协议分布映射
     */
    std::map<std::string, uint64_t> getProtocolDistribution() const;
    
    /**
     * @brief 获取端口分布
     * @return 端口分布映射
     */
    std::map<int, uint64_t> getPortDistribution() const;
    
    /**
     * @brief 检查是否正在分析
     * @return 分析状态
     */
    bool isAnalyzing() const { return analyzing_; }
    
    /**
     * @brief 重置统计信息
     */
    void resetStats();
    
    /**
     * @brief 设置分析选项
     * @param windowSizeSeconds 统计窗口大小（秒）
     * @param maxConnections 最大连接数
     * @param maxHosts 最大主机数
     */
    void setAnalysisOptions(int windowSizeSeconds = 60, 
                           int maxConnections = 10000, 
                           int maxHosts = 1000);
    
    /**
     * @brief 导出报告
     * @param filename 文件名
     * @param format 格式（json/csv/txt）
     * @return 是否成功
     */
    bool exportReport(const std::string& filename, const std::string& format = "json");
    
    /**
     * @brief 检测异常流量
     * @return 异常信息列表
     */
    std::vector<std::string> detectAnomalies();

private:
    std::atomic<bool> analyzing_;       // 分析状态
    std::unique_ptr<PacketCapture> packetCapture_;  // 数据包捕获器
    
    // 统计信息
    TrafficStats stats_;
    std::map<std::string, ConnectionInfo> connections_;  // 连接映射
    std::map<std::string, HostInfo> hosts_;              // 主机映射
    std::map<std::string, uint64_t> protocolStats_;      // 协议统计
    std::map<int, uint64_t> portStats_;                  // 端口统计
    
    // 时间窗口统计
    std::queue<std::pair<std::chrono::steady_clock::time_point, uint64_t>> packetTimeWindow_;
    std::queue<std::pair<std::chrono::steady_clock::time_point, uint64_t>> byteTimeWindow_;
    
    // 分析选项
    int windowSizeSeconds_;             // 统计窗口大小
    int maxConnections_;                // 最大连接数
    int maxHosts_;                      // 最大主机数
    
    // 线程同步
    mutable std::mutex statsMutex_;
    mutable std::mutex connectionsMutex_;
    mutable std::mutex hostsMutex_;
    
    // 分析线程
    std::thread analysisThread_;
    
    // 异常检测阈值
    struct AnomalyThresholds {
        double maxPacketsPerSecond = 10000.0;
        double maxBytesPerSecond = 100 * 1024 * 1024; // 100MB/s
        uint64_t maxConnectionsPerHost = 1000;
        uint64_t maxPacketsPerConnection = 100000;
    } thresholds_;
    
    /**
     * @brief 更新时间窗口统计
     */
    void updateTimeWindowStats();
    
    /**
     * @brief 清理过期连接
     */
    void cleanupExpiredConnections();
    
    /**
     * @brief 清理过期主机
     */
    void cleanupExpiredHosts();
    
    /**
     * @brief 获取连接键
     * @param packet 数据包信息
     * @return 连接键字符串
     */
    std::string getConnectionKey(const PacketInfo& packet);
    
    /**
     * @brief 解析主机名
     * @param ipAddress IP地址
     * @return 主机名
     */
    std::string resolveHostname(const std::string& ipAddress);
    
    /**
     * @brief 检测端口扫描
     * @return 是否检测到端口扫描
     */
    bool detectPortScan();
    
    /**
     * @brief 检测DDoS攻击
     * @return 是否检测到DDoS攻击
     */
    bool detectDDoS();
    
    /**
     * @brief 检测异常连接
     * @return 异常连接列表
     */
    std::vector<std::string> detectAbnormalConnections();
    
    /**
     * @brief 分析线程函数
     */
    void analysisLoop();
    
    /**
     * @brief 清理资源
     */
    void cleanup();
};
