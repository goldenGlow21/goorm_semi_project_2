cmake_minimum_required(VERSION 3.30)
project(c_modules C)

set(CMAKE_C_STANDARD 11)
# pkg-config 사용
find_package(PkgConfig REQUIRED)

# GLib 찾기
pkg_check_modules(GLIB2 REQUIRED glib-2.0)

# GLib 관련 include 및 link 디렉토리 추가
include_directories(${GLIB2_INCLUDE_DIRS})
link_directories(${GLIB2_LIBRARY_DIRS})
add_definitions(${GLIB2_CFLAGS_OTHER})

# 프로젝트 관련 include 디렉토리 추가
include_directories(port_scanner/c_modules)
add_executable(c_modules common.c
        thpool.c
        ack_scan.c
        null_scan.c
        tcp_connect.c
        tcp_fin_scan.c
        tcp_half_scan.c
udp_scan.c
xmas_scan.c)
# GLib 라이브러리 링크
target_link_libraries(c_modules ${GLIB2_LIBRARIES})


#sudo apt-get glib2.0 -y
