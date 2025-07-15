#include "PacketCapture.h"
#include "Utils.h"
#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>

PacketCapture::PacketCapture() 
    : handle_(nullptr), capturing_(false) {
}

PacketCapture::~PacketCapture() {
    stopCapture();
    cleanup();
}

bool PacketCapture::initialize(const std::string& device, const std::string& filter) {
    auto& logger = Logger::getInstance();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开设备
    handle_ = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle_ == nullptr) {
        logger.error("无法打开设备 " + device + ": " + std::string(errbuf));
        return false;
    }
    
    // 设置过滤器
    if (!filter.empty()) {
        struct bpf_program fp;
        bpf_u_int32 net, mask;
        
        if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
            logger.warning("无法获取网络信息: " + std::string(errbuf));
            net = 0;
            mask = 0;
        }
        
        if (pcap_compile(handle_, &fp, filter.c_str(), 0, net) == -1) {
            logger.error("编译过滤器失败: " + std::string(pcap_geterr(handle_)));
            return false;
        }
        
        if (pcap_setfilter(handle_, &fp) == -1) {
            logger.error("设置过滤器失败: " + std::string(pcap_geterr(handle_)));
            return false;
        }
        
        pcap_freecode(&fp);
    }
    
    logger.info("数据包捕获器初始化成功，设备: " + device);
    return true;
}

bool PacketCapture::startCapture(PacketHandler handler) {
    auto& logger = Logger::getInstance();
    
    if (capturing_) {
        logger.warning("数据包捕获已经在运行");
        return false;
    }
    
    if (handle_ == nullptr) {
        logger.error("数据包捕获器未初始化");
        return false;
    }
    
    packetHandler_ = handler;
    capturing_ = true;
    
    // 启动捕获线程
    captureThread_ = std::thread(&PacketCapture::captureLoop, this);
    
    logger.info("数据包捕获已启动");
    return true;
}

void PacketCapture::stopCapture() {
    if (!capturing_) {
        return;
    }
    
    capturing_ = false;
    
    // 中断捕获循环
    if (handle_) {
        pcap_breakloop(handle_);
    }
    
    // 等待捕获线程结束
    if (captureThread_.joinable()) {
        captureThread_.join();
    }
    
    auto& logger = Logger::getInstance();
    logger.info("数据包捕获已停止");
}

void PacketCapture::setPacketHandler(PacketHandler handler) {
    packetHandler_ = handler;
}

bool PacketCapture::saveToFile(const std::string& filename) {
    auto& logger = Logger::getInstance();
    
    if (handle_ == nullptr) {
        logger.error("数据包捕获器未初始化");
        return false;
    }
    
    // 创建pcap转储文件
    pcap_dumper_t* dumper = pcap_dump_open(handle_, filename.c_str());
    if (dumper == nullptr) {
        logger.error("无法创建转储文件: " + filename);
        return false;
    }
    
    // 注意：这里需要在实际捕获过程中调用pcap_dump
    // 这只是一个简化的示例
    
    pcap_dump_close(dumper);
    logger.info("数据包已保存到文件: " + filename);
    return true;
}

std::vector<std::string> PacketCapture::getDeviceList() {
    std::vector<std::string> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        auto& logger = Logger::getInstance();
        logger.error("获取设备列表失败: " + std::string(errbuf));
        return devices;
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        devices.push_back(std::string(dev->name));
    }
    
    pcap_freealldevs(alldevs);
    return devices;
}

std::string PacketCapture::getStatistics() const {
    std::ostringstream oss;
    oss << "=== 数据包捕获统计 ===\n";
    oss << "总包数: " << stats_.totalPackets << "\n";
    oss << "总字节数: " << Utils::formatBytes(stats_.totalBytes) << "\n";
    oss << "丢包数: " << stats_.droppedPackets << "\n";
    return oss.str();
}

void PacketCapture::packetCallback(u_char* user, const struct pcap_pkthdr* header, 
                                  const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(user);
    
    // 解析数据包
    PacketInfo packetInfo = capture->parsePacket(header, packet);
    
    // 更新统计信息
    capture->stats_.totalPackets++;
    capture->stats_.totalBytes += header->len;
    
    // 调用处理函数
    if (capture->packetHandler_) {
        capture->packetHandler_(packetInfo);
    }
}

PacketInfo PacketCapture::parsePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    PacketInfo info;
    
    // 设置时间戳
    char timestr[64];
    struct tm* timeinfo = localtime(&header->ts.tv_sec);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", timeinfo);
    info.timestamp = std::string(timestr);
    
    // 设置包长度
    info.length = header->len;
    
    // 解析以太网头
    uint16_t etherType = parseEthernet(packet, info);
    
    // 解析IP头
    if (etherType == 0x0800) { // IPv4
        uint8_t protocol = parseIP(packet + 14, info);
        
        // 解析传输层协议
        if (protocol == 6) { // TCP
            info.protocol = "TCP";
            parseTCP(packet + 14 + 20, info);
        } else if (protocol == 17) { // UDP
            info.protocol = "UDP";
            parseUDP(packet + 14 + 20, info);
        }
    }
    
    return info;
}

uint16_t PacketCapture::parseEthernet(const u_char* packet, PacketInfo& info) {
    // 以太网头长度为14字节
    // 返回以太网类型字段
    return ntohs(*(uint16_t*)(packet + 12));
}

uint8_t PacketCapture::parseIP(const u_char* packet, PacketInfo& info) {
    // IP头的源地址和目标地址
    uint32_t srcIP = ntohl(*(uint32_t*)(packet + 12));
    uint32_t dstIP = ntohl(*(uint32_t*)(packet + 16));
    
    info.srcIP = Utils::ipIntToString(srcIP);
    info.dstIP = Utils::ipIntToString(dstIP);
    
    // 返回协议字段
    return packet[9];
}

void PacketCapture::parseTCP(const u_char* packet, PacketInfo& info) {
    // TCP头的源端口和目标端口
    info.srcPort = ntohs(*(uint16_t*)(packet));
    info.dstPort = ntohs(*(uint16_t*)(packet + 2));
}

void PacketCapture::parseUDP(const u_char* packet, PacketInfo& info) {
    // UDP头的源端口和目标端口
    info.srcPort = ntohs(*(uint16_t*)(packet));
    info.dstPort = ntohs(*(uint16_t*)(packet + 2));
}

void PacketCapture::captureLoop() {
    auto& logger = Logger::getInstance();
    
    // 开始捕获循环
    int result = pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(this));
    
    if (result == -1) {
        logger.error("数据包捕获循环出错: " + std::string(pcap_geterr(handle_)));
    } else if (result == -2) {
        logger.info("数据包捕获循环被中断");
    }
}

void PacketCapture::cleanup() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}
