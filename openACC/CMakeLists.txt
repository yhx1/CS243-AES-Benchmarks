cmake_minimum_required(VERSION 3.9)

project(AES)

SET(CMAKE_CXX_COMPILER /opt/pgi/linux86-64/19.10/bin/pgc++)
SET(CMAKE_C_COMPILER /opt/pgi/linux86-64/19.10/bin/pgcc)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -acc -ta=multicore -Minfo")

add_executable(MP_oacc
    AES.cpp
    openacc.cpp
    )
