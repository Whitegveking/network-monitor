#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <getopt.h>
#include <csignal>
#include <unistd.h>
#include "NetworkMonitor.h"
#include "Utils.h"

// 全局变量
NetworkMonitor* g_monitor = nullptr;
bool g_running = true;

/**
 * @brief 信号处理函数
 * @param signum 信号编号
 */
void signalHandler(int signum) {
    std::cout << "\n接收到信号 " << signum << "，正在关闭..." << std::endl;
    g_running = false;
    if (g_monitor) {
        g_monitor->stopMonitoring();
    }
}

/**
 * @brief 显示帮助信息
 * @param programName 程序名称
 */
void showHelp(const char* programName) {
    std::cout << "网络监控工具 v1.0.0\n\n";
    std::cout << "用法: " << programName << " [选项]\n\n";
    std::cout << "选项:\n";
    std::cout << "  -h, --help              显示帮助信息\n";
    std::cout << "  -v, --version           显示版本信息\n";
    std::cout << "  -i, --interface <网卡>  指定网络接口\n";
    std::cout << "  -t, --time <秒>         监控时间（0表示无限）\n";
    std::cout << "  -s, --scan <主机>       扫描主机端口\n";
    std::cout << "  -p, --ports <范围>      端口范围（如: 1-1000）\n";
    std::cout << "  -c, --capture <文件>    捕获数据包到文件\n";
    std::cout << "  -f, --filter <过滤器>   BPF过滤器\n";
    std::cout << "  -a, --analyze           分析流量\n";
    std::cout << "  -l, --list              列出网络接口\n";
    std::cout << "  -d, --daemon            后台运行\n";
    std::cout << "  --log-file <文件>       日志文件路径\n";
    std::cout << "  --log-level <级别>      日志级别（debug/info/warning/error）\n";
    std::cout << "\n";
    std::cout << "示例:\n";
    std::cout << "  " << programName << " -i eth0 -t 60                    # 监控eth0接口60秒\n";
    std::cout << "  " << programName << " -s 192.168.1.1 -p 1-1000        # 扫描端口1-1000\n";
    std::cout << "  " << programName << " -i eth0 -c capture.pcap          # 捕获数据包\n";
    std::cout << "  " << programName << " -i eth0 -f \"tcp port 80\" -a      # 分析HTTP流量\n";
    std::cout << "  " << programName << " -l                               # 列出网络接口\n";
    std::cout << "\n";
}

/**
 * @brief 显示版本信息
 */
void showVersion() {
    std::cout << "网络监控工具 v1.0.0\n";
    std::cout << "编译时间: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "作者: 实习生项目\n";
}

/**
 * @brief 解析端口范围
 * @param portRange 端口范围字符串
 * @param startPort 起始端口
 * @param endPort 结束端口
 * @return 是否解析成功
 */
bool parsePortRange(const std::string& portRange, int& startPort, int& endPort) {
    auto parts = Utils::split(portRange, '-');
    if (parts.size() == 1) {
        // 单个端口
        startPort = endPort = Utils::stringToInt(parts[0]);
        return Utils::isValidPort(startPort);
    } else if (parts.size() == 2) {
        // 端口范围
        startPort = Utils::stringToInt(parts[0]);
        endPort = Utils::stringToInt(parts[1]);
        return Utils::isValidPort(startPort) && Utils::isValidPort(endPort) && startPort <= endPort;
    }
    return false;
}

/**
 * @brief 主函数
 * @param argc 参数个数
 * @param argv 参数数组
 * @return 退出码
 */
int main(int argc, char* argv[]) {
    // 检查root权限
    if (!Utils::hasRootPrivileges()) {
        std::cerr << "错误: 需要root权限运行此程序\n";
        std::cerr << "请使用: sudo " << argv[0] << " [选项]\n";
        return 1;
    }
    
    // 设置信号处理
    Utils::setSignalHandler(SIGINT, signalHandler);
    Utils::setSignalHandler(SIGTERM, signalHandler);
    
    // 命令行选项
    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"interface", required_argument, 0, 'i'},
        {"time", required_argument, 0, 't'},
        {"scan", required_argument, 0, 's'},
        {"ports", required_argument, 0, 'p'},
        {"capture", required_argument, 0, 'c'},
        {"filter", required_argument, 0, 'f'},
        {"analyze", no_argument, 0, 'a'},
        {"list", no_argument, 0, 'l'},
        {"daemon", no_argument, 0, 'd'},
        {"log-file", required_argument, 0, 1001},
        {"log-level", required_argument, 0, 1002},
        {0, 0, 0, 0}
    };
    
    // 解析命令行参数
    std::string interface = "";  // 暂时为空，稍后动态设置
    int monitorTime = 0;
    std::string scanHost;
    std::string portRange = "1-1000";
    std::string captureFile;
    std::string filter;
    bool analyze = false;
    bool listInterfaces = false;
    bool daemon = false;
    std::string logFile;
    std::string logLevel = "info";
    
    int opt;
    while ((opt = getopt_long(argc, argv, "hvi:t:s:p:c:f:ald", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                showHelp(argv[0]);
                return 0;
            case 'v':
                showVersion();
                return 0;
            case 'i':
                interface = optarg;
                break;
            case 't':
                monitorTime = Utils::stringToInt(optarg);
                break;
            case 's':
                scanHost = optarg;
                break;
            case 'p':
                portRange = optarg;
                break;
            case 'c':
                captureFile = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'a':
                analyze = true;
                break;
            case 'l':
                listInterfaces = true;
                break;
            case 'd':
                daemon = true;
                break;
            case 1001:
                logFile = optarg;
                break;
            case 1002:
                logLevel = optarg;
                break;
            default:
                std::cerr << "使用 " << argv[0] << " --help 查看帮助信息\n";
                return 1;
        }
    }
    
    // 配置日志
    auto& logger = Logger::getInstance();
    if (!logFile.empty()) {
        if (!logger.setLogFile(logFile)) {
            std::cerr << "警告: 无法打开日志文件 " << logFile << std::endl;
        }
    }
    
    // 设置日志级别
    if (logLevel == "debug") {
        logger.setLogLevel(LogLevel::DEBUG);
    } else if (logLevel == "info") {
        logger.setLogLevel(LogLevel::INFO);
    } else if (logLevel == "warning") {
        logger.setLogLevel(LogLevel::WARNING);
    } else if (logLevel == "error") {
        logger.setLogLevel(LogLevel::ERROR);
    }
    
    // 后台运行
    if (daemon) {
        if (::daemon(1, 0) != 0) {
            std::cerr << "错误: 无法启动后台进程\n";
            return 1;
        }
    }
    
    // 创建网络监控器
    NetworkMonitor monitor;
    g_monitor = &monitor;
    
    logger.info("网络监控工具启动");
    
    // 初始化监控器
    if (!monitor.initialize()) {
        std::cerr << "错误: 初始化网络监控器失败\n";
        logger.error("初始化网络监控器失败");
        return 1;
    }
    
    // 如果没有指定接口，自动选择默认接口
    if (interface.empty()) {
        auto interfaces = monitor.getNetworkInterfaces();
        // 优先选择非回环接口
        for (const auto& iface : interfaces) {
            if (iface != "lo" && iface != "any" && 
                iface.find("bluetooth") == std::string::npos &&
                iface.find("nflog") == std::string::npos &&
                iface.find("nfqueue") == std::string::npos &&
                iface.find("dbus") == std::string::npos) {
                interface = iface;
                break;
            }
        }
        // 如果没找到合适的接口，使用第一个可用接口
        if (interface.empty() && !interfaces.empty()) {
            interface = interfaces[0];
        }
        logger.info("自动选择网络接口: " + interface);
    }
    
    // 执行相应操作
    if (listInterfaces) {
        // 列出网络接口
        std::cout << "可用网络接口:\n";
        auto interfaces = monitor.getNetworkInterfaces();
        for (const auto& iface : interfaces) {
            std::cout << "  " << iface << "\n";
        }
        return 0;
    }
    
    if (!scanHost.empty()) {
        // 端口扫描
        int startPort, endPort;
        if (!parsePortRange(portRange, startPort, endPort)) {
            std::cerr << "错误: 无效的端口范围 " << portRange << "\n";
            return 1;
        }
        
        std::cout << "正在扫描主机 " << scanHost << " 端口 " << startPort << "-" << endPort << "...\n";
        logger.info("开始端口扫描: " + scanHost + " 端口 " + std::to_string(startPort) + "-" + std::to_string(endPort));
        
        auto openPorts = monitor.scanPorts(scanHost, startPort, endPort);
        
        if (openPorts.empty()) {
            std::cout << "未发现开放端口\n";
        } else {
            std::cout << "发现开放端口:\n";
            for (int port : openPorts) {
                std::cout << "  " << port << "\n";
            }
        }
        return 0;
    }
    
    if (!captureFile.empty()) {
        // 数据包捕获
        std::cout << "正在捕获数据包到文件 " << captureFile << "...\n";
        logger.info("开始数据包捕获: " + interface + " -> " + captureFile);
        
        if (!monitor.capturePackets(interface, filter, captureFile)) {
            std::cerr << "错误: 数据包捕获失败\n";
            logger.error("数据包捕获失败");
            return 1;
        }
        
        std::cout << "数据包捕获完成\n";
        return 0;
    }
    
    if (analyze) {
        // 流量分析
        std::cout << "正在分析网络流量...\n";
        logger.info("开始流量分析: " + interface);
        
        if (!monitor.analyzeTraffic(interface)) {
            std::cerr << "错误: 流量分析失败\n";
            logger.error("流量分析失败");
            return 1;
        }
        
        // 显示实时统计信息
        while (g_running && monitor.isMonitoring()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            std::cout << monitor.getStatistics() << std::endl;
        }
        
        return 0;
    }
    
    // 默认：网络监控
    std::cout << "正在监控网络接口 " << interface;
    if (monitorTime > 0) {
        std::cout << " 持续 " << monitorTime << " 秒";
    }
    std::cout << "...\n";
    std::cout << "按 Ctrl+C 停止监控\n\n";
    
    logger.info("开始网络监控: " + interface + " 时间: " + std::to_string(monitorTime));
    
    if (!monitor.startMonitoring(interface, monitorTime)) {
        std::cerr << "错误: 启动网络监控失败\n";
        logger.error("启动网络监控失败");
        return 1;
    }
    
    // 显示实时统计信息
    auto lastUpdate = std::chrono::steady_clock::now();
    while (g_running && monitor.isMonitoring()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate);
        
        if (elapsed.count() >= 5) {
            std::cout << "\033[2J\033[H"; // 清屏
            std::cout << "网络监控统计 - " << Utils::getCurrentTimeString() << "\n";
            std::cout << "监控接口: " << interface << "\n";
            std::cout << "运行时间: " << Utils::formatDuration(
                std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate).count()) << "\n\n";
            std::cout << monitor.getStatistics() << std::endl;
            lastUpdate = now;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "\n网络监控已停止\n";
    logger.info("网络监控已停止");
    
    return 0;
}
