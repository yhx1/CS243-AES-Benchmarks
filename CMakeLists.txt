cmake_minimum_required(VERSION 3.9)

project(AES)

include_directories(${TBB_INCLUDE_DIRS})
add_definitions(${TBB_DEFINITIONS})

find_package(OpenMP REQUIRED)
find_package(TBB REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

add_executable(serial
    AES.cpp
    serial.cpp
    )

add_executable(MP_pthread
    AES.cpp
    pthread.cpp
    )

add_executable(MP_omp
    AES.cpp
    openmp.cpp
    )

add_executable(MP_tbb
    AES.cpp
    tbb.cpp
    )

target_link_libraries(MP_pthread pthread)
target_link_libraries(MP_omp OpenMP::OpenMP_CXX)
target_link_libraries(MP_tbb ${TBB_LIBRARIES})
