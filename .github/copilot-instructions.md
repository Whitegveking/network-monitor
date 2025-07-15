<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Network Monitor Project Instructions

这是一个C++网络监控工具项目，专注于网络编程和系统编程。

## 项目特点

- 使用现代C++17标准
- 基于CMake构建系统
- 网络编程重点：套接字编程、数据包处理
- 系统编程：多线程、信号处理、进程间通信
- 使用libpcap库进行数据包捕获

## 编码规范

- 遵循现代C++最佳实践
- 使用RAII模式管理资源
- 智能指针优于原始指针
- 异常安全的代码设计
- 详细的注释和文档

## 关键技术栈

- **网络编程**: 原始套接字、TCP/UDP编程
- **数据包处理**: libpcap、协议解析
- **并发编程**: std::thread、std::mutex
- **文件I/O**: 日志记录、配置文件
- **CLI界面**: 命令行参数处理

## 开发重点

1. 网络安全：权限检查、输入验证
2. 性能优化：内存管理、I/O效率
3. 错误处理：异常处理、资源清理
4. 跨平台兼容性：Linux优先，考虑可移植性

当生成代码时，请确保：
- 包含适当的错误处理
- 使用现代C++特性
- 添加详细的注释
- 考虑线程安全
- 遵循项目的代码风格
