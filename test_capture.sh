#!/bin/bash

# 测试网络数据包捕获功能
cd /home/white/桌面/network\ monitor/build

echo "启动网络监控工具..."
sudo ./NetworkMonitor -a &
MONITOR_PID=$!

echo "等待2秒让程序初始化..."
sleep 2

echo "生成网络流量..."
ping -c 3 8.8.8.8 &
curl -s http://www.baidu.com > /dev/null &
wget -q -O /dev/null http://www.sina.com.cn &

echo "等待5秒让程序捕获数据包..."
sleep 5

echo "停止监控程序..."
sudo kill -SIGINT $MONITOR_PID

echo "等待程序退出..."
wait $MONITOR_PID

echo "测试完成"
