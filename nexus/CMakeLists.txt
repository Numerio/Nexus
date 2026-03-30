cmake_minimum_required(VERSION 3.25 FATAL_ERROR)
project(nexus VERSION 0.3.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D__KERNEL__ -DMODULE)

#TODO print a resume of variables for debug purposes
#TODO native builds should build nexus natively
option(BUILD_LOCAL_NEXUS "Build Nexus in the host environment" OFF)

set(NEXUS_CLEAN_FILES
    ${CMAKE_BINARY_DIR}/nexus-dkms_1_all.deb
    ${CMAKE_BINARY_DIR}/nexus-dkms_1.dsc
	${CMAKE_BINARY_DIR}/nexus-dkms_1_amd64.buildinfo
	${CMAKE_BINARY_DIR}/nexus-dkms_1.tar.gz
	${CMAKE_BINARY_DIR}/nexus-dkms_1_amd64.changes
)

if(BUILD_LOCAL_NEXUS)
    if(VITRUVIAN_KERNEL_HEADERS)
        set(NEXUS_KDIR "${VITRUVIAN_KERNEL_HEADERS}")
    else()
        set(NEXUS_KDIR "/lib/modules/${KERNEL_RELEASE}/build")
    endif()
    add_custom_target(nexus
        COMMAND ${CMAKE_COMMAND} -E echo "Nexus...building locally (KDIR=${NEXUS_KDIR})"
        COMMAND make KDIR=${NEXUS_KDIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
else()
    add_custom_target(nexus
        COMMAND ${CMAKE_COMMAND} -E echo "Nexus will not be built locally"
    )
endif()

add_custom_command(
	TARGET nexus
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E echo "Building nexus-dkms package..."
	COMMAND bash "-c" "dpkg-buildpackage -uc -us"
	#TODO this should be done more cleanly
	COMMAND bash "-c" "mv ../nexus-dkms_1* ${CMAKE_BINARY_DIR}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../"
)

set_property(
        TARGET nexus
        APPEND
        PROPERTY ADDITIONAL_CLEAN_FILES ${NEXUS_CLEAN_FILES}
)
