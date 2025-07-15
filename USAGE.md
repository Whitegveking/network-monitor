# 网络监控工具使用指南

## 快速开始

### 1. 编译项目
```bash
cd /home/white/桌面/network\ monitor
mkdir -p build && cd build
cmake ..
make
```

### 2. 基本使用

#### 查看帮助
```bash
sudo ./NetworkMonitor --help
```

#### 列出网络接口
```bash
sudo ./NetworkMonitor -l
```

#### 扫描端口
```bash
# 扫描本地主机常见端口
sudo ./NetworkMonitor -s 127.0.0.1 -p 20-80

# 扫描远程主机
sudo ./NetworkMonitor -s 192.168.1.1 -p 1-1000
```

#### 监控网络流量
```bash
# 监控指定网络接口
sudo ./NetworkMonitor -i ens33 -t 60

# 无限期监控
sudo ./NetworkMonitor -i ens33
```

#### 捕获数据包
```bash
# 捕获所有数据包
sudo ./NetworkMonitor -i ens33 -c capture.pcap

# 捕获特定协议的数据包
sudo ./NetworkMonitor -i ens33 -f "tcp port 80" -c http_traffic.pcap
```

#### 分析流量
```bash
# 分析网络流量
sudo ./NetworkMonitor -i ens33 -a
```

## 高级功能

### 1. 过滤器语法
程序支持BPF（Berkeley Packet Filter）过滤器语法：

```bash
# 只捕获TCP流量
sudo ./NetworkMonitor -i ens33 -f "tcp"

# 只捕获HTTP流量
sudo ./NetworkMonitor -i ens33 -f "tcp port 80"

# 捕获特定主机的流量
sudo ./NetworkMonitor -i ens33 -f "host 192.168.1.100"

# 捕获SIP协议流量
sudo ./NetworkMonitor -i ens33 -f "port 5060"
```

### 2. 日志配置
```bash
# 设置日志文件
sudo ./NetworkMonitor -i ens33 --log-file /var/log/netmon.log

# 设置日志级别
sudo ./NetworkMonitor -i ens33 --log-level debug
```

### 3. 后台运行
```bash
# 后台运行监控
sudo ./NetworkMonitor -i ens33 -d --log-file /var/log/netmon.log
```

## 实际应用场景

### 1. 网络故障排查
```bash
# 监控特定接口的流量
sudo ./NetworkMonitor -i ens33 -t 300

# 分析异常流量
sudo ./NetworkMonitor -i ens33 -a
```

### 2. 安全监控
```bash
# 监控可疑端口扫描
sudo ./NetworkMonitor -s 192.168.1.0/24 -p 1-1000

# 捕获网络攻击流量
sudo ./NetworkMonitor -i ens33 -f "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
```

### 3. 性能监控
```bash
# 监控网络带宽使用
sudo ./NetworkMonitor -i ens33 -t 3600

# 分析网络连接
sudo ./NetworkMonitor -i ens33 -a
```

## 注意事项

1. **权限要求**：程序需要root权限才能运行，因为需要访问网络接口和创建原始套接字。

2. **网络接口**：使用 `-l` 选项查看可用的网络接口，选择合适的接口进行监控。

3. **过滤器语法**：BPF过滤器语法功能强大，可以精确控制捕获的数据包类型。

4. **性能影响**：长时间运行监控可能会产生大量数据，注意磁盘空间和系统性能。

5. **法律合规**：仅在授权的网络环境中使用，遵守相关法律法规。

## 扩展功能

项目采用模块化设计，可以轻松扩展以下功能：

- 更多协议支持（HTTPS、DNS、DHCP等）
- 图形界面
- 数据库存储
- 实时告警
- 网络拓扑发现
- 流量统计报告

## 故障排除

### 编译错误
- 确保安装了必要的依赖库：`libpcap-dev`、`libjsoncpp-dev`
- 检查CMake版本是否符合要求

### 运行错误
- 确保以root权限运行
- 检查网络接口名称是否正确
- 验证过滤器语法

### 性能问题
- 合理设置监控时间
- 使用适当的过滤器减少数据量
- 考虑在高性能机器上运行
