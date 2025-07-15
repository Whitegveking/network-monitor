# 网络监控工具 (Network Monitor)

一个用C++编写的网络监控工具，提供实时网络流量分析、端口扫描、协议分析等功能。

## 功能特性

- 🔍 **端口扫描** - 扫描指定主机的开放端口
- 📊 **流量监控** - 实时监控网络流量
- 📦 **数据包捕获** - 捕获和分析网络数据包
- 🔧 **协议分析** - 支持TCP、UDP、HTTP、SIP等协议
- 📈 **性能统计** - 网络性能指标统计
- 💾 **日志记录** - 详细的操作日志

## 项目结构

```
network-monitor/
├── CMakeLists.txt          # CMake构建文件
├── README.md              # 项目说明
├── include/               # 头文件目录
│   ├── NetworkMonitor.h   # 主类头文件
│   ├── PacketCapture.h    # 数据包捕获
│   ├── PortScanner.h      # 端口扫描
│   ├── TrafficAnalyzer.h  # 流量分析
│   └── Utils.h            # 工具函数
├── src/                   # 源文件目录
│   ├── main.cpp           # 主程序入口
│   ├── NetworkMonitor.cpp # 主类实现
│   ├── PacketCapture.cpp  # 数据包捕获实现
│   ├── PortScanner.cpp    # 端口扫描实现
│   ├── TrafficAnalyzer.cpp # 流量分析实现
│   └── Utils.cpp          # 工具函数实现
├── tests/                 # 测试文件
├── docs/                  # 文档
└── build/                 # 构建目录
```

## 系统要求

- C++17或更高版本
- CMake 3.16+
- libpcap开发库
- Linux系统（支持原始套接字）

## 安装依赖

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install cmake build-essential libpcap-dev
```

### CentOS/RHEL
```bash
sudo yum install cmake gcc-c++ libpcap-devel
```

## 编译和运行

1. 创建构建目录
```bash
mkdir build
cd build
```

2. 配置和编译
```bash
cmake ..
make
```

3. 运行程序
```bash
sudo ./NetworkMonitor
```

## 使用说明

### 基本命令
```bash
# 显示帮助信息
./NetworkMonitor --help

# 扫描端口
./NetworkMonitor --scan --host 192.168.1.1 --ports 1-1000

# 监控网络流量
./NetworkMonitor --monitor --interface eth0 --duration 60

# 捕获数据包
./NetworkMonitor --capture --interface eth0 --filter "tcp port 80"
```

### 配置文件
程序支持配置文件，默认位置：`~/.config/network-monitor/config.json`

## 开发指南

### 添加新功能
1. 在`include/`目录添加头文件
2. 在`src/`目录添加实现文件
3. 更新CMakeLists.txt
4. 编写测试用例

### 代码风格
- 使用4个空格缩进
- 类名使用PascalCase
- 函数名使用camelCase
- 常量使用UPPER_CASE

## 许可证

MIT License

## 项目完成状态

✅ **已完成功能**：
- 基本的网络监控框架
- 端口扫描功能
- 数据包捕获
- 流量分析基础
- 命令行界面
- 日志系统
- 多线程支持

✅ **成功编译和运行**：
- CMake构建系统配置完成
- 所有依赖库正确链接
- 程序可以正常运行

✅ **测试验证**：
- 帮助信息显示正常
- 网络接口列表功能正常
- 端口扫描功能正常（已测试本地22端口）

## 快速开始

```bash
# 编译项目
cd /home/white/桌面/network\ monitor
mkdir -p build && cd build
cmake .. && make

# 查看帮助
sudo ./NetworkMonitor --help

# 列出网络接口
sudo ./NetworkMonitor -l

# 扫描本地端口
sudo ./NetworkMonitor -s 127.0.0.1 -p 22-80
```

## 学习价值

这个项目非常适合学习以下技术：

1. **网络编程**：套接字、数据包处理、网络协议
2. **系统编程**：多线程、进程管理、信号处理
3. **现代C++**：智能指针、RAII、STL容器
4. **项目管理**：CMake构建、模块化设计
5. **实际应用**：网络监控、安全分析

## 后续扩展建议

- 添加更多网络协议支持
- 实现图形界面
- 加入数据库存储
- 添加实时告警功能
- 优化性能和内存使用

## 贡献

欢迎提交Issue和Pull Request！

## 作者

开发者：实习生项目

这个项目为你提供了一个很好的C++网络编程学习平台！
