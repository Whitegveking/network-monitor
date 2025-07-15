#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <pcap/pcap.h>

/**
 * @brief 数据包信息结构
 */
struct PacketInfo {
    std::string timestamp;      // 时间戳
    std::string srcIP;          // 源IP地址
    std::string dstIP;          // 目标IP地址
    uint16_t srcPort;           // 源端口
    uint16_t dstPort;           // 目标端口
    std::string protocol;       // 协议类型
    uint32_t length;            // 数据包长度
    std::string payload;        // 载荷数据（可选）
};

/**
 * @brief 数据包捕获类
 * 
 * 负责网络数据包的捕获和初步解析
 */
class PacketCapture {
public:
    /**
     * @brief 数据包处理回调函数类型
     */
    using PacketHandler = std::function<void(const PacketInfo&)>;
    
    /**
     * @brief 构造函数
     */
    PacketCapture();
    
    /**
     * @brief 析构函数
     */
    ~PacketCapture();
    
    /**
     * @brief 初始化捕获器
     * @param device 网络设备名称
     * @param filter 过滤规则（BPF格式）
     * @return 是否成功
     */
    bool initialize(const std::string& device, const std::string& filter = "");
    
    /**
     * @brief 开始捕获
     * @param handler 数据包处理回调函数
     * @return 是否成功
     */
    bool startCapture(PacketHandler handler);
    
    /**
     * @brief 停止捕获
     */
    void stopCapture();
    
    /**
     * @brief 保存到文件
     * @param filename 文件名
     * @return 是否成功
     */
    bool saveToFile(const std::string& filename);
    
    /**
     * @brief 获取设备列表
     * @return 设备列表
     */
    static std::vector<std::string> getDeviceList();
    
    /**
     * @brief 检查是否正在捕获
     * @return 捕获状态
     */
    bool isCapturing() const { return capturing_; }
    
    /**
     * @brief 获取捕获统计
     * @return 统计信息
     */
    std::string getStatistics() const;

private:
    pcap_t* handle_;                    // pcap句柄
    std::atomic<bool> capturing_;       // 捕获状态
    std::thread captureThread_;         // 捕获线程
    PacketHandler packetHandler_;       // 数据包处理函数
    
    // 统计信息
    struct CaptureStats {
        uint64_t totalPackets = 0;
        uint64_t totalBytes = 0;
        uint64_t droppedPackets = 0;
    } stats_;
    
    /**
     * @brief 数据包回调函数（C风格）
     * @param user 用户数据
     * @param header 数据包头
     * @param packet 数据包数据
     */
    static void packetCallback(u_char* user, const struct pcap_pkthdr* header, 
                              const u_char* packet);
    
    /**
     * @brief 解析数据包
     * @param header 数据包头
     * @param packet 数据包数据
     * @return 数据包信息
     */
    PacketInfo parsePacket(const struct pcap_pkthdr* header, const u_char* packet);
    
    /**
     * @brief 解析以太网头
     * @param packet 数据包数据
     * @param info 数据包信息
     * @return 下一层协议类型
     */
    uint16_t parseEthernet(const u_char* packet, PacketInfo& info);
    
    /**
     * @brief 解析IP头
     * @param packet 数据包数据
     * @param info 数据包信息
     * @return 下一层协议类型
     */
    uint8_t parseIP(const u_char* packet, PacketInfo& info);
    
    /**
     * @brief 解析TCP头
     * @param packet 数据包数据
     * @param info 数据包信息
     */
    void parseTCP(const u_char* packet, PacketInfo& info);
    
    /**
     * @brief 解析UDP头
     * @param packet 数据包数据
     * @param info 数据包信息
     */
    void parseUDP(const u_char* packet, PacketInfo& info);
    
    /**
     * @brief 捕获线程函数
     */
    void captureLoop();
    
    /**
     * @brief 清理资源
     */
    void cleanup();
};
