cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project(nexus VERSION 0.2.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D__KERNEL__ -DMODULE)

message(STATUS "Target kernel release: ${KERNEL_RELEASE}")

add_custom_target(
   nexus
   COMMAND make KDIR=/usr/lib/modules/${KERNEL_RELEASE}/build BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

INCLUDE(CPack)

install(FILES ./nexus.ko DESTINATION /lib/modules/${KERNEL_RELEASE}/kernel/drivers/nexus)
