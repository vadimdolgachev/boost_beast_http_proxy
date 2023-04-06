cmake_minimum_required(VERSION 3.25)
project(boost_beast_http_proxy)

find_package(OpenSSL REQUIRED)
find_package(fmt REQUIRED)
find_package(Boost REQUIRED)


set(CMAKE_CXX_STANDARD 17)

add_executable(boost_beast_http_proxy main.cpp root_certificates.hpp)

target_link_libraries(boost_beast_http_proxy PRIVATE fmt::fmt Boost::boost
        OpenSSL::SSL
        OpenSSL::Crypto)
