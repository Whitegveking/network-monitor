#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>

// 前向声明
class PacketCapture;
class PortScanner;
class TrafficAnalyzer;

/**
 * @brief 网络监控工具主类
 * 
 * 这是整个网络监控工具的核心类，负责协调各个组件的工作
 */
class NetworkMonitor {
public:
    /**
     * @brief 构造函数
     */
    NetworkMonitor();
    
    /**
     * @brief 析构函数
     */
    ~NetworkMonitor();
    
    /**
     * @brief 初始化监控器
     * @return 初始化是否成功
     */
    bool initialize();
    
    /**
     * @brief 开始监控
     * @param interface 网络接口名称
     * @param duration 监控时长（秒）
     * @return 是否成功开始监控
     */
    bool startMonitoring(const std::string& interface, int duration = 0);
    
    /**
     * @brief 停止监控
     */
    void stopMonitoring();
    
    /**
     * @brief 扫描端口
     * @param host 目标主机
     * @param startPort 起始端口
     * @param endPort 结束端口
     * @return 开放端口列表
     */
    std::vector<int> scanPorts(const std::string& host, int startPort, int endPort);
    
    /**
     * @brief 捕获数据包
     * @param interface 网络接口
     * @param filter 过滤规则
     * @param outputFile 输出文件
     * @return 是否成功
     */
    bool capturePackets(const std::string& interface, const std::string& filter, 
                       const std::string& outputFile);
    
    /**
     * @brief 分析流量
     * @param interface 网络接口
     * @return 是否成功
     */
    bool analyzeTraffic(const std::string& interface);
    
    /**
     * @brief 获取网络接口列表
     * @return 网络接口列表
     */
    std::vector<std::string> getNetworkInterfaces();
    
    /**
     * @brief 检查是否正在监控
     * @return 监控状态
     */
    bool isMonitoring() const { return monitoring_; }
    
    /**
     * @brief 获取统计信息
     * @return 统计信息字符串
     */
    std::string getStatistics() const;

private:
    // 组件实例
    std::unique_ptr<PacketCapture> packetCapture_;
    std::unique_ptr<PortScanner> portScanner_;
    std::unique_ptr<TrafficAnalyzer> trafficAnalyzer_;
    
    // 监控状态
    std::atomic<bool> monitoring_;
    std::thread monitoringThread_;
    
    // 线程同步
    mutable std::mutex statsMutex_;
    
    // 统计信息
    struct Statistics {
        uint64_t totalPackets = 0;
        uint64_t totalBytes = 0;
        uint64_t tcpPackets = 0;
        uint64_t udpPackets = 0;
        uint64_t httpPackets = 0;
        uint64_t sipPackets = 0;
    } stats_;
    
    /**
     * @brief 监控线程函数
     * @param interface 网络接口
     * @param duration 监控时长
     */
    void monitoringLoop(const std::string& interface, int duration);
    
    /**
     * @brief 更新统计信息
     */
    void updateStatistics();
    
    /**
     * @brief 清理资源
     */
    void cleanup();
};
