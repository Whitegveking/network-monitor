#include "NetworkMonitor.h"
#include "PacketCapture.h"
#include "PortScanner.h"
#include "TrafficAnalyzer.h"
#include "Utils.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>

NetworkMonitor::NetworkMonitor() 
    : monitoring_(false) {
    // 初始化组件
    packetCapture_ = std::make_unique<PacketCapture>();
    portScanner_ = std::make_unique<PortScanner>();
    trafficAnalyzer_ = std::make_unique<TrafficAnalyzer>();
}

NetworkMonitor::~NetworkMonitor() {
    stopMonitoring();
    cleanup();
}

bool NetworkMonitor::initialize() {
    auto& logger = Logger::getInstance();
    
    // 检查权限
    if (!Utils::hasRootPrivileges()) {
        logger.error("需要root权限才能运行网络监控");
        return false;
    }
    
    // 初始化统计信息
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Statistics{};
    
    logger.info("网络监控器初始化完成");
    return true;
}

bool NetworkMonitor::startMonitoring(const std::string& interface, int duration) {
    auto& logger = Logger::getInstance();
    
    if (monitoring_) {
        logger.warning("监控已经在运行中");
        return false;
    }
    
    monitoring_ = true;
    
    // 启动监控线程
    monitoringThread_ = std::thread(&NetworkMonitor::monitoringLoop, this, interface, duration);
    
    logger.info("网络监控已启动，接口: " + interface);
    return true;
}

void NetworkMonitor::stopMonitoring() {
    if (!monitoring_) {
        return;
    }
    
    monitoring_ = false;
    
    // 停止各个组件
    if (packetCapture_) {
        packetCapture_->stopCapture();
    }
    if (portScanner_) {
        portScanner_->stopScan();
    }
    if (trafficAnalyzer_) {
        trafficAnalyzer_->stopAnalysis();
    }
    
    // 等待监控线程结束
    if (monitoringThread_.joinable()) {
        monitoringThread_.join();
    }
    
    auto& logger = Logger::getInstance();
    logger.info("网络监控已停止");
}

std::vector<int> NetworkMonitor::scanPorts(const std::string& host, int startPort, int endPort) {
    auto& logger = Logger::getInstance();
    logger.info("开始端口扫描: " + host + " 端口 " + std::to_string(startPort) + "-" + std::to_string(endPort));
    
    if (!portScanner_) {
        logger.error("端口扫描器未初始化");
        return {};
    }
    
    auto results = portScanner_->scanPortRange(host, startPort, endPort);
    
    std::vector<int> openPorts;
    for (const auto& result : results) {
        if (result.isOpen) {
            openPorts.push_back(result.port);
        }
    }
    
    logger.info("端口扫描完成，发现 " + std::to_string(openPorts.size()) + " 个开放端口");
    return openPorts;
}

bool NetworkMonitor::capturePackets(const std::string& interface, const std::string& filter, 
                                   const std::string& outputFile) {
    auto& logger = Logger::getInstance();
    logger.info("开始数据包捕获: " + interface + " -> " + outputFile);
    
    if (!packetCapture_) {
        logger.error("数据包捕获器未初始化");
        return false;
    }
    
    // 初始化捕获器
    if (!packetCapture_->initialize(interface, filter)) {
        logger.error("初始化数据包捕获器失败");
        return false;
    }
    
    // 设置数据包处理回调
    auto packetHandler = [this](const PacketInfo& packet) {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalPackets++;
        stats_.totalBytes += packet.length;
        
        if (packet.protocol == "TCP") {
            stats_.tcpPackets++;
        } else if (packet.protocol == "UDP") {
            stats_.udpPackets++;
        }
        
        // 检查特定协议
        if (packet.dstPort == 80 || packet.srcPort == 80) {
            stats_.httpPackets++;
        } else if (packet.dstPort == 5060 || packet.srcPort == 5060) {
            stats_.sipPackets++;
        }
    };
    
    // 开始捕获
    if (!packetCapture_->startCapture(packetHandler)) {
        logger.error("启动数据包捕获失败");
        return false;
    }
    
    // 保存到文件
    if (!outputFile.empty()) {
        if (!packetCapture_->saveToFile(outputFile)) {
            logger.error("保存数据包到文件失败: " + outputFile);
            return false;
        }
    }
    
    logger.info("数据包捕获成功");
    return true;
}

bool NetworkMonitor::analyzeTraffic(const std::string& interface) {
    auto& logger = Logger::getInstance();
    logger.info("开始流量分析: " + interface);
    
    if (monitoring_) {
        logger.warning("监控已经在运行中");
        return false;
    }
    
    if (!trafficAnalyzer_) {
        logger.error("流量分析器未初始化");
        return false;
    }
    
    monitoring_ = true;
    
    bool result = trafficAnalyzer_->startAnalysis(interface);
    if (!result) {
        monitoring_ = false;
    }
    
    return result;
}

std::vector<std::string> NetworkMonitor::getNetworkInterfaces() {
    return PacketCapture::getDeviceList();
}

std::string NetworkMonitor::getStatistics() const {
    std::ostringstream oss;
    oss << "=== 网络监控统计 ===\n";
    
    // 如果使用流量分析器，从流量分析器获取统计信息
    if (trafficAnalyzer_) {
        TrafficStats trafficStats = trafficAnalyzer_->getTrafficStats();
        oss << "总包数: " << trafficStats.totalPackets << "\n";
        oss << "总字节数: " << Utils::formatBytes(trafficStats.totalBytes) << "\n";
        oss << "TCP包数: " << trafficStats.tcpPackets << "\n";
        oss << "UDP包数: " << trafficStats.udpPackets << "\n";
        oss << "ICMP包数: " << trafficStats.icmpPackets << "\n";
        oss << "HTTP包数: " << trafficStats.httpPackets << "\n";
        oss << "HTTPS包数: " << trafficStats.httpsPackets << "\n";
        oss << "DNS包数: " << trafficStats.dnsPackets << "\n";
        oss << "SIP包数: " << trafficStats.sipPackets << "\n";
        oss << "平均包大小: " << std::fixed << std::setprecision(2) << trafficStats.avgPacketSize << " 字节\n";
        oss << "每秒包数: " << std::fixed << std::setprecision(2) << trafficStats.packetsPerSecond << "\n";
        oss << "每秒字节数: " << Utils::formatBytes(static_cast<uint64_t>(trafficStats.bytesPerSecond)) << "\n";
    } else {
        // 否则使用本地统计信息
        std::lock_guard<std::mutex> lock(statsMutex_);
        oss << "总包数: " << stats_.totalPackets << "\n";
        oss << "总字节数: " << Utils::formatBytes(stats_.totalBytes) << "\n";
        oss << "TCP包数: " << stats_.tcpPackets << "\n";
        oss << "UDP包数: " << stats_.udpPackets << "\n";
        oss << "HTTP包数: " << stats_.httpPackets << "\n";
        oss << "SIP包数: " << stats_.sipPackets << "\n";
        
        if (stats_.totalPackets > 0) {
            oss << "平均包大小: " << (stats_.totalBytes / stats_.totalPackets) << " 字节\n";
        }
    }
    
    return oss.str();
}

void NetworkMonitor::monitoringLoop(const std::string& interface, int duration) {
    auto& logger = Logger::getInstance();
    auto startTime = std::chrono::steady_clock::now();
    
    // 启动数据包捕获
    if (!capturePackets(interface, "", "")) {
        logger.error("启动数据包捕获失败");
        monitoring_ = false;
        return;
    }
    
    // 监控循环
    while (monitoring_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // 检查是否达到时间限制
        if (duration > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime);
            if (elapsed.count() >= duration) {
                logger.info("监控时间已到，停止监控");
                break;
            }
        }
        
        // 更新统计信息
        updateStatistics();
    }
    
    monitoring_ = false;
}

void NetworkMonitor::updateStatistics() {
    // 这里可以添加更多的统计信息更新逻辑
    // 例如：计算网络流量速率、检测异常等
}

void NetworkMonitor::cleanup() {
    // 清理资源
    packetCapture_.reset();
    portScanner_.reset();
    trafficAnalyzer_.reset();
}
