#include "TrafficAnalyzer.h"
#include "Utils.h"
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>

TrafficAnalyzer::TrafficAnalyzer() 
    : analyzing_(false), windowSizeSeconds_(60), 
      maxConnections_(10000), maxHosts_(1000) {
}

TrafficAnalyzer::~TrafficAnalyzer() {
    stopAnalysis();
    cleanup();
}

bool TrafficAnalyzer::startAnalysis(const std::string& interface) {
    auto& logger = Logger::getInstance();
    
    if (analyzing_) {
        logger.warning("流量分析已经在运行");
        return false;
    }
    
    analyzing_ = true;
    
    // 创建数据包捕获器
    packetCapture_ = std::make_unique<PacketCapture>();
    
    // 初始化捕获器
    if (!packetCapture_->initialize(interface)) {
        logger.error("初始化数据包捕获器失败");
        analyzing_ = false;
        return false;
    }
    
    // 设置数据包处理回调
    auto packetHandler = [this](const PacketInfo& packet) {
        processPacket(packet);
    };
    
    // 开始捕获
    if (!packetCapture_->startCapture(packetHandler)) {
        logger.error("启动数据包捕获失败");
        analyzing_ = false;
        return false;
    }
    
    // 启动分析线程
    analysisThread_ = std::thread(&TrafficAnalyzer::analysisLoop, this);
    
    logger.info("流量分析已启动，接口: " + interface);
    return true;
}

void TrafficAnalyzer::stopAnalysis() {
    if (!analyzing_) {
        return;
    }
    
    analyzing_ = false;
    
    // 停止数据包捕获
    if (packetCapture_) {
        packetCapture_->stopCapture();
    }
    
    // 等待分析线程结束
    if (analysisThread_.joinable()) {
        analysisThread_.join();
    }
    
    auto& logger = Logger::getInstance();
    logger.info("流量分析已停止");
}

void TrafficAnalyzer::processPacket(const PacketInfo& packet) {
    auto now = std::chrono::steady_clock::now();
    
    // 更新基本统计信息
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        
        stats_.totalPackets++;
        stats_.totalBytes += packet.length;
        
        if (packet.protocol == "TCP") {
            stats_.tcpPackets++;
        } else if (packet.protocol == "UDP") {
            stats_.udpPackets++;
        } else if (packet.protocol == "ICMP") {
            stats_.icmpPackets++;
        }
        
        // 检查应用层协议
        if (packet.dstPort == 80 || packet.srcPort == 80) {
            stats_.httpPackets++;
        } else if (packet.dstPort == 443 || packet.srcPort == 443) {
            stats_.httpsPackets++;
        } else if (packet.dstPort == 53 || packet.srcPort == 53) {
            stats_.dnsPackets++;
        } else if (packet.dstPort == 5060 || packet.srcPort == 5060) {
            stats_.sipPackets++;
        }
        
        // 更新时间窗口统计
        packetTimeWindow_.push({now, 1});
        byteTimeWindow_.push({now, packet.length});
    }
    
    // 更新连接信息
    {
        std::lock_guard<std::mutex> lock(connectionsMutex_);
        
        std::string connKey = getConnectionKey(packet);
        auto& conn = connections_[connKey];
        
        if (conn.srcIP.empty()) {
            conn.srcIP = packet.srcIP;
            conn.dstIP = packet.dstIP;
            conn.srcPort = packet.srcPort;
            conn.dstPort = packet.dstPort;
            conn.protocol = packet.protocol;
        }
        
        conn.packets++;
        conn.bytes += packet.length;
        conn.lastSeen = now;
    }
    
    // 更新主机信息
    {
        std::lock_guard<std::mutex> lock(hostsMutex_);
        
        // 更新源主机信息
        auto& srcHost = hosts_[packet.srcIP];
        if (srcHost.ipAddress.empty()) {
            srcHost.ipAddress = packet.srcIP;
            srcHost.hostname = resolveHostname(packet.srcIP);
            srcHost.firstSeen = now;
        }
        srcHost.totalPackets++;
        srcHost.totalBytes += packet.length;
        srcHost.lastSeen = now;
        
        // 添加活跃端口
        if (std::find(srcHost.activePorts.begin(), srcHost.activePorts.end(), packet.srcPort) 
            == srcHost.activePorts.end()) {
            srcHost.activePorts.push_back(packet.srcPort);
        }
        
        // 更新目标主机信息
        auto& dstHost = hosts_[packet.dstIP];
        if (dstHost.ipAddress.empty()) {
            dstHost.ipAddress = packet.dstIP;
            dstHost.hostname = resolveHostname(packet.dstIP);
            dstHost.firstSeen = now;
        }
        dstHost.totalPackets++;
        dstHost.totalBytes += packet.length;
        dstHost.lastSeen = now;
        
        // 添加活跃端口
        if (std::find(dstHost.activePorts.begin(), dstHost.activePorts.end(), packet.dstPort) 
            == dstHost.activePorts.end()) {
            dstHost.activePorts.push_back(packet.dstPort);
        }
    }
    
    // 更新协议统计
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        protocolStats_[packet.protocol]++;
        portStats_[packet.dstPort]++;
    }
}

TrafficStats TrafficAnalyzer::getTrafficStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    TrafficStats stats = stats_;
    
    // 计算平均值
    if (stats.totalPackets > 0) {
        stats.avgPacketSize = static_cast<double>(stats.totalBytes) / stats.totalPackets;
    }
    
    // 计算速率（简化版本）
    // 这里简化实现，实际应用中需要更复杂的时间窗口计算
    stats.packetsPerSecond = static_cast<double>(stats.totalPackets) / windowSizeSeconds_;
    stats.bytesPerSecond = static_cast<double>(stats.totalBytes) / windowSizeSeconds_;
    
    return stats;
}

std::vector<ConnectionInfo> TrafficAnalyzer::getConnections() const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    std::vector<ConnectionInfo> connections;
    for (const auto& pair : connections_) {
        connections.push_back(pair.second);
    }
    
    // 按字节数排序
    std::sort(connections.begin(), connections.end(), 
              [](const ConnectionInfo& a, const ConnectionInfo& b) {
                  return a.bytes > b.bytes;
              });
    
    return connections;
}

std::vector<HostInfo> TrafficAnalyzer::getHosts() const {
    std::lock_guard<std::mutex> lock(hostsMutex_);
    
    std::vector<HostInfo> hosts;
    for (const auto& pair : hosts_) {
        hosts.push_back(pair.second);
    }
    
    // 按字节数排序
    std::sort(hosts.begin(), hosts.end(), 
              [](const HostInfo& a, const HostInfo& b) {
                  return a.totalBytes > b.totalBytes;
              });
    
    return hosts;
}

std::map<std::string, uint64_t> TrafficAnalyzer::getProtocolDistribution() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return protocolStats_;
}

std::map<int, uint64_t> TrafficAnalyzer::getPortDistribution() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return portStats_;
}

void TrafficAnalyzer::resetStats() {
    std::lock_guard<std::mutex> statsLock(statsMutex_);
    std::lock_guard<std::mutex> connLock(connectionsMutex_);
    std::lock_guard<std::mutex> hostLock(hostsMutex_);
    
    stats_ = TrafficStats{};
    connections_.clear();
    hosts_.clear();
    protocolStats_.clear();
    portStats_.clear();
    
    // 清空时间窗口
    while (!packetTimeWindow_.empty()) {
        packetTimeWindow_.pop();
    }
    while (!byteTimeWindow_.empty()) {
        byteTimeWindow_.pop();
    }
}

void TrafficAnalyzer::setAnalysisOptions(int windowSizeSeconds, int maxConnections, int maxHosts) {
    windowSizeSeconds_ = windowSizeSeconds;
    maxConnections_ = maxConnections;
    maxHosts_ = maxHosts;
}

bool TrafficAnalyzer::exportReport(const std::string& filename, const std::string& format) {
    auto& logger = Logger::getInstance();
    
    if (format == "json") {
        std::ofstream file(filename);
        if (!file.is_open()) {
            logger.error("无法创建报告文件: " + filename);
            return false;
        }
        
        // 简化的JSON格式输出
        auto stats = getTrafficStats();
        
        file << "{\n";
        file << "  \"statistics\": {\n";
        file << "    \"totalPackets\": " << stats.totalPackets << ",\n";
        file << "    \"totalBytes\": " << stats.totalBytes << ",\n";
        file << "    \"tcpPackets\": " << stats.tcpPackets << ",\n";
        file << "    \"udpPackets\": " << stats.udpPackets << ",\n";
        file << "    \"avgPacketSize\": " << stats.avgPacketSize << ",\n";
        file << "    \"packetsPerSecond\": " << stats.packetsPerSecond << ",\n";
        file << "    \"bytesPerSecond\": " << stats.bytesPerSecond << "\n";
        file << "  },\n";
        
        file << "  \"connections\": [\n";
        auto connections = getConnections();
        for (size_t i = 0; i < connections.size(); ++i) {
            const auto& conn = connections[i];
            file << "    {\n";
            file << "      \"srcIP\": \"" << conn.srcIP << "\",\n";
            file << "      \"dstIP\": \"" << conn.dstIP << "\",\n";
            file << "      \"srcPort\": " << conn.srcPort << ",\n";
            file << "      \"dstPort\": " << conn.dstPort << ",\n";
            file << "      \"protocol\": \"" << conn.protocol << "\",\n";
            file << "      \"packets\": " << conn.packets << ",\n";
            file << "      \"bytes\": " << conn.bytes << "\n";
            file << "    }";
            if (i < connections.size() - 1) file << ",";
            file << "\n";
        }
        file << "  ],\n";
        
        file << "  \"hosts\": [\n";
        auto hosts = getHosts();
        for (size_t i = 0; i < hosts.size(); ++i) {
            const auto& host = hosts[i];
            file << "    {\n";
            file << "      \"ipAddress\": \"" << host.ipAddress << "\",\n";
            file << "      \"hostname\": \"" << host.hostname << "\",\n";
            file << "      \"totalPackets\": " << host.totalPackets << ",\n";
            file << "      \"totalBytes\": " << host.totalBytes << ",\n";
            file << "      \"activePorts\": [";
            for (size_t j = 0; j < host.activePorts.size(); ++j) {
                file << host.activePorts[j];
                if (j < host.activePorts.size() - 1) file << ",";
            }
            file << "]\n";
            file << "    }";
            if (i < hosts.size() - 1) file << ",";
            file << "\n";
        }
        file << "  ]\n";
        file << "}\n";
        
        file.close();
        
        logger.info("报告已导出到: " + filename);
        return true;
    }
    
    logger.error("不支持的报告格式: " + format);
    return false;
}

std::vector<std::string> TrafficAnalyzer::detectAnomalies() {
    std::vector<std::string> anomalies;
    
    auto stats = getTrafficStats();
    
    // 检查高流量
    if (stats.packetsPerSecond > thresholds_.maxPacketsPerSecond) {
        anomalies.push_back("检测到高包频率: " + std::to_string(stats.packetsPerSecond) + " pps");
    }
    
    if (stats.bytesPerSecond > thresholds_.maxBytesPerSecond) {
        anomalies.push_back("检测到高流量: " + Utils::formatBytes(stats.bytesPerSecond) + "/s");
    }
    
    // 检查连接异常
    auto connections = getConnections();
    for (const auto& conn : connections) {
        if (conn.packets > thresholds_.maxPacketsPerConnection) {
            anomalies.push_back("连接 " + conn.srcIP + ":" + std::to_string(conn.srcPort) + 
                               " -> " + conn.dstIP + ":" + std::to_string(conn.dstPort) + 
                               " 包数异常: " + std::to_string(conn.packets));
        }
    }
    
    // 检查主机异常
    auto hosts = getHosts();
    for (const auto& host : hosts) {
        if (host.activePorts.size() > thresholds_.maxConnectionsPerHost) {
            anomalies.push_back("主机 " + host.ipAddress + " 连接数异常: " + 
                               std::to_string(host.activePorts.size()));
        }
    }
    
    return anomalies;
}

void TrafficAnalyzer::updateTimeWindowStats() {
    auto now = std::chrono::steady_clock::now();
    auto windowStart = now - std::chrono::seconds(windowSizeSeconds_);
    
    // 清理过期的时间窗口数据
    while (!packetTimeWindow_.empty() && packetTimeWindow_.front().first < windowStart) {
        packetTimeWindow_.pop();
    }
    
    while (!byteTimeWindow_.empty() && byteTimeWindow_.front().first < windowStart) {
        byteTimeWindow_.pop();
    }
}

void TrafficAnalyzer::cleanupExpiredConnections() {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto expireTime = now - std::chrono::minutes(5); // 5分钟过期
    
    for (auto it = connections_.begin(); it != connections_.end();) {
        if (it->second.lastSeen < expireTime) {
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
    
    // 限制连接数量
    if (connections_.size() > maxConnections_) {
        // 删除最旧的连接
        // 这里需要实现LRU策略
    }
}

void TrafficAnalyzer::cleanupExpiredHosts() {
    std::lock_guard<std::mutex> lock(hostsMutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto expireTime = now - std::chrono::hours(1); // 1小时过期
    
    for (auto it = hosts_.begin(); it != hosts_.end();) {
        if (it->second.lastSeen < expireTime) {
            it = hosts_.erase(it);
        } else {
            ++it;
        }
    }
    
    // 限制主机数量
    if (hosts_.size() > maxHosts_) {
        // 删除最旧的主机
        // 这里需要实现LRU策略
    }
}

std::string TrafficAnalyzer::getConnectionKey(const PacketInfo& packet) {
    return packet.srcIP + ":" + std::to_string(packet.srcPort) + "->" + 
           packet.dstIP + ":" + std::to_string(packet.dstPort) + "(" + packet.protocol + ")";
}

std::string TrafficAnalyzer::resolveHostname(const std::string& ipAddress) {
    // 简化的主机名解析
    // 实际应用中应该使用getnameinfo等函数
    return ipAddress;
}

void TrafficAnalyzer::analysisLoop() {
    while (analyzing_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // 更新时间窗口统计
        updateTimeWindowStats();
        
        // 清理过期数据
        cleanupExpiredConnections();
        cleanupExpiredHosts();
    }
}

void TrafficAnalyzer::cleanup() {
    packetCapture_.reset();
}
