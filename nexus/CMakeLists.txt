cmake_minimum_required(VERSION 3.25 FATAL_ERROR)
project(nexus VERSION 0.3.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D__KERNEL__ -DMODULE)

message(STATUS "Host kernel release: ${KERNEL_RELEASE}")

#TODO add opt to skip local kernel build
add_custom_target(
   nexus
   COMMAND make KDIR=/usr/lib/modules/${KERNEL_RELEASE}/build WORKING_DIR=${CMAKE_CURRENT_BINARY_DIR}
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_command(
	TARGET nexus
	COMMAND bash "-c" "dpkg-buildpackage -uc -us"
	#TODO this should be done more cleanly
	COMMAND bash "-c" "mv ../nexus-dkms_1* ${CMAKE_BINARY_DIR}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../"
)
