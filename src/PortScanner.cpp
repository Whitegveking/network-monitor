#include "PortScanner.h"
#include "Utils.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <future>

// 常见服务映射
std::map<int, std::string> PortScanner::commonServices_;

PortScanner::PortScanner() 
    : scanning_(false), totalPorts_(0), scannedPorts_(0), 
      scanDelay_(0), maxRetries_(1) {
    initializeServiceMap();
}

PortScanner::~PortScanner() {
    stopScan();
}

PortScanResult PortScanner::scanPort(const std::string& host, int port, 
                                    ScanType type, int timeout) {
    switch (type) {
        case ScanType::TCP_CONNECT:
            return tcpConnectScan(host, port, timeout);
        case ScanType::TCP_SYN:
            return tcpSynScan(host, port, timeout);
        case ScanType::UDP:
            return udpScan(host, port, timeout);
        default:
            return tcpConnectScan(host, port, timeout);
    }
}

std::vector<PortScanResult> PortScanner::scanPortRange(const std::string& host, 
                                                      int startPort, int endPort,
                                                      ScanType type, int threads) {
    auto& logger = Logger::getInstance();
    
    scanning_ = true;
    totalPorts_ = endPort - startPort + 1;
    scannedPorts_ = 0;
    
    std::vector<PortScanResult> results;
    std::vector<std::future<PortScanResult>> futures;
    
    logger.info("开始扫描主机 " + host + " 端口范围 " + 
                std::to_string(startPort) + "-" + std::to_string(endPort));
    
    // 创建线程池
    int activeThreads = 0;
    for (int port = startPort; port <= endPort && scanning_; ++port) {
        // 限制并发线程数
        while (activeThreads >= threads && scanning_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            
            // 检查完成的任务
            for (auto it = futures.begin(); it != futures.end();) {
                if (it->wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
                    results.push_back(it->get());
                    it = futures.erase(it);
                    activeThreads--;
                    scannedPorts_++;
                } else {
                    ++it;
                }
            }
        }
        
        if (!scanning_) break;
        
        // 启动新的扫描任务
        futures.emplace_back(std::async(std::launch::async, 
            [this, host, port, type]() {
                return scanPort(host, port, type, 1000);
            }));
        activeThreads++;
        
        // 扫描延迟
        if (scanDelay_ > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(scanDelay_));
        }
    }
    
    // 等待所有任务完成
    for (auto& future : futures) {
        results.push_back(future.get());
        scannedPorts_++;
    }
    
    scanning_ = false;
    
    // 统计开放端口
    int openPorts = 0;
    for (const auto& result : results) {
        if (result.isOpen) {
            openPorts++;
        }
    }
    
    logger.info("端口扫描完成，发现 " + std::to_string(openPorts) + " 个开放端口");
    return results;
}

std::vector<PortScanResult> PortScanner::scanCommonPorts(const std::string& host, ScanType type) {
    auto commonPorts = getCommonPorts();
    std::vector<PortScanResult> results;
    
    scanning_ = true;
    totalPorts_ = commonPorts.size();
    scannedPorts_ = 0;
    
    for (int port : commonPorts) {
        if (!scanning_) break;
        
        results.push_back(scanPort(host, port, type, 1000));
        scannedPorts_++;
    }
    
    scanning_ = false;
    return results;
}

void PortScanner::stopScan() {
    scanning_ = false;
}

double PortScanner::getProgress() const {
    if (totalPorts_ == 0) {
        return 0.0;
    }
    return (static_cast<double>(scannedPorts_) / totalPorts_) * 100.0;
}

void PortScanner::setScanOptions(int delayMs, int maxRetries) {
    scanDelay_ = delayMs;
    maxRetries_ = maxRetries;
}

std::string PortScanner::getServiceName(int port, const std::string& protocol) {
    if (commonServices_.find(port) != commonServices_.end()) {
        return commonServices_[port];
    }
    return "unknown";
}

std::vector<int> PortScanner::getCommonPorts() {
    return {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,  // 常见TCP端口
        80, 443, 8080, 8443, 3000, 3306, 5432, 6379,      // Web和数据库
        135, 139, 445, 1433, 1521, 3389,                  // Windows服务
        5060, 5061, 5080,                                 // SIP
        1723, 1701, 500, 4500                             // VPN
    };
}

PortScanResult PortScanner::tcpConnectScan(const std::string& host, int port, int timeout) {
    PortScanResult result;
    result.port = port;
    result.isOpen = false;
    result.service = getServiceName(port, "tcp");
    result.responseTime = 0;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // 创建套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return result;
    }
    
    // 设置非阻塞模式
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    // 设置服务器地址
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
        close(sockfd);
        return result;
    }
    
    // 尝试连接
    int connectResult = connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    if (connectResult == 0) {
        // 立即连接成功
        result.isOpen = true;
    } else if (errno == EINPROGRESS) {
        // 连接正在进行，使用select等待
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(sockfd, &writeSet);
        
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        
        int selectResult = select(sockfd + 1, nullptr, &writeSet, nullptr, &tv);
        
        if (selectResult > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                result.isOpen = true;
            }
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    close(sockfd);
    return result;
}

PortScanResult PortScanner::tcpSynScan(const std::string& host, int port, int timeout) {
    // TCP SYN扫描需要原始套接字，需要root权限
    // 这里提供一个简化的实现，实际应用中需要构造TCP SYN包
    auto& logger = Logger::getInstance();
    logger.warning("TCP SYN扫描需要root权限和原始套接字支持");
    
    // 回退到TCP连接扫描
    return tcpConnectScan(host, port, timeout);
}

PortScanResult PortScanner::udpScan(const std::string& host, int port, int timeout) {
    PortScanResult result;
    result.port = port;
    result.isOpen = false;
    result.service = getServiceName(port, "udp");
    result.responseTime = 0;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // 创建UDP套接字
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return result;
    }
    
    // 设置服务器地址
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr) <= 0) {
        close(sockfd);
        return result;
    }
    
    // 发送UDP数据包
    const char* testData = "test";
    ssize_t sendResult = sendto(sockfd, testData, strlen(testData), 0, 
                               (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    if (sendResult > 0) {
        // 设置接收超时
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // 尝试接收响应
        char buffer[1024];
        ssize_t recvResult = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        
        if (recvResult > 0) {
            result.isOpen = true;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    close(sockfd);
    return result;
}

std::string PortScanner::detectServiceVersion(const std::string& host, int port) {
    // 简化的服务版本检测
    // 实际应用中需要发送特定的探测包来检测服务版本
    return "unknown";
}

std::string PortScanner::resolveHostname(const std::string& hostname) {
    // 简化的主机名解析
    if (Utils::isValidIP(hostname)) {
        return hostname;
    }
    
    // 这里应该使用getaddrinfo等函数进行DNS解析
    return hostname;
}

void PortScanner::initializeServiceMap() {
    commonServices_[21] = "ftp";
    commonServices_[22] = "ssh";
    commonServices_[23] = "telnet";
    commonServices_[25] = "smtp";
    commonServices_[53] = "dns";
    commonServices_[80] = "http";
    commonServices_[110] = "pop3";
    commonServices_[143] = "imap";
    commonServices_[443] = "https";
    commonServices_[993] = "imaps";
    commonServices_[995] = "pop3s";
    commonServices_[3306] = "mysql";
    commonServices_[5432] = "postgresql";
    commonServices_[6379] = "redis";
    commonServices_[5060] = "sip";
    commonServices_[5061] = "sips";
    commonServices_[5080] = "sip";
    commonServices_[3389] = "rdp";
    commonServices_[1433] = "mssql";
    commonServices_[1521] = "oracle";
}
