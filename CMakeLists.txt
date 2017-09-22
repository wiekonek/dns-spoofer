cmake_minimum_required(VERSION 3.7)
project(dns_spoofer)

set(CMAKE_CXX_STANDARD 14)


set(SOURCE_FILES main.cpp ArpSpoofer.cpp ArpSpoofer.h consts.h DnsSpoofer.cpp DnsSpoofer.h)
add_executable(dns_spoofer ${SOURCE_FILES})

target_link_libraries(dns_spoofer pcap net udns)
