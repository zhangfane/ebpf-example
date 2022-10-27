cmake_minimum_required(VERSION 3.16)
project(untitled C)

set(CMAKE_C_STANDARD 11)

add_executable(untitled pid/pid.bpf.c)
add_executable(untitled2 helloWorld/helloworld.bpf.c)
add_executable(untitled3 pid/pid.c)

#
include_directories(/root/bpftool/src/libbpf/include)
