cmake_minimum_required(VERSION 3.16)
project(NetworkMonitor VERSION 1.0.0)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# 查找依赖库
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

# 查找 jsoncpp 库
pkg_check_modules(JSONCPP jsoncpp)

# 包含目录
include_directories(include)

# 源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.h")

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# 链接库
target_link_libraries(${PROJECT_NAME} 
    Threads::Threads
    pcap
    jsoncpp
)

# 安装目标
install(TARGETS ${PROJECT_NAME}
    DESTINATION bin
)

# 编译选项
target_compile_options(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:-g -DDEBUG>
    $<$<CONFIG:Release>:-O3 -DNDEBUG>
)
