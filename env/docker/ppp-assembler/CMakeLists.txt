cmake_minimum_required(VERSION 3.12)
project(flow_assemble CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

add_executable(flow_assemble flow_assemble.cpp)

# Uses the CMake package installed by `cmake --install` of PcapPlusPlus. The
# PcapPlusPlus::Pcap++ target carries the include dirs and transitive deps
# (Packet++, Common++, libpcap, pthread).
find_package(PcapPlusPlus REQUIRED)
target_link_libraries(flow_assemble PUBLIC PcapPlusPlus::Pcap++)
