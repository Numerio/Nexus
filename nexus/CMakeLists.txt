cmake_minimum_required(VERSION 3.25 FATAL_ERROR)
project(nexus VERSION 0.3.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-D__KERNEL__ -DMODULE)

#TODO print a resume of variables for debug purposes
#TODO native builds should build nexus natively
option(BUILD_LOCAL_NEXUS "Build Nexus in the host environment" OFF)

# An epoch is required, not cosmetic: the published version is the bare
# integer 1, and every 0.x sorts below it.
#   dpkg --compare-versions 0.3.0+git0.1f68b84 gt 1    -> false
#   dpkg --compare-versions 1:0.3.0+git0.1f68b84 gt 1  -> true
# Bump only if some future scheme has to outrank this one.
set(NEXUS_PKG_EPOCH "1")

# The build number orders the versions; a sha does not, because dpkg
# compares digit runs numerically and letter runs as text. It is handed in
# by whatever ran the build, the same VOS_PKG_REV the rest of the tree
# uses, so a package and the system it installs name the same build.
if(DEFINED ENV{VOS_PKG_REV} AND NOT "$ENV{VOS_PKG_REV}" STREQUAL "")
	set(NEXUS_PKG_REV "$ENV{VOS_PKG_REV}")
else()
	set(NEXUS_PKG_REV "0")
endif()

execute_process(
	COMMAND git rev-parse --short HEAD
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	OUTPUT_VARIABLE NEXUS_GIT_SHA
	OUTPUT_STRIP_TRAILING_WHITESPACE
	ERROR_QUIET)
if(NOT NEXUS_GIT_SHA)
	set(NEXUS_GIT_SHA "unknown")
endif()

# The sha is read at configure time: reconfigure whenever HEAD moves, or a
# build mixes two versions (changelog vs. file names).
execute_process(
	COMMAND git rev-parse --absolute-git-dir
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	OUTPUT_VARIABLE NEXUS_GIT_DIR
	OUTPUT_STRIP_TRAILING_WHITESPACE
	ERROR_QUIET)
foreach(_head HEAD logs/HEAD)
	if(NEXUS_GIT_DIR AND EXISTS "${NEXUS_GIT_DIR}/${_head}")
		set_property(DIRECTORY APPEND PROPERTY
			CMAKE_CONFIGURE_DEPENDS "${NEXUS_GIT_DIR}/${_head}")
	endif()
endforeach()
execute_process(
	COMMAND git log -1 --format=%cD
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	OUTPUT_VARIABLE NEXUS_DEB_DATE
	OUTPUT_STRIP_TRAILING_WHITESPACE
	ERROR_QUIET)
if(NOT NEXUS_DEB_DATE)
	string(TIMESTAMP NEXUS_DEB_DATE "%a, %d %b %Y %H:%M:%S +0000" UTC)
endif()

# Native package, so no -revision: a non-native version would need an
# .orig.tar.gz that dpkg-buildpackage -uc -us does not have here.
set(NEXUS_DEB_VERSION
	"${NEXUS_PKG_EPOCH}:${PROJECT_VERSION}+git${NEXUS_PKG_REV}.${NEXUS_GIT_SHA}")
message(STATUS "nexus-dkms version: ${NEXUS_DEB_VERSION}")

# dpkg-buildpackage reads debian/changelog from the source tree. Generate
# it into the build dir and copy it in at build time: `ninja clean` removes
# the in-tree copy and does not reconfigure.
set(NEXUS_CHANGELOG "${CMAKE_CURRENT_BINARY_DIR}/changelog")
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/../debian/changelog.in"
	"${NEXUS_CHANGELOG}"
	@ONLY)

# dpkg leaves the epoch out of filenames.
set(NEXUS_DEB_FILEVER "${PROJECT_VERSION}+git${NEXUS_PKG_REV}.${NEXUS_GIT_SHA}")
set(NEXUS_CLEAN_FILES
	${CMAKE_BINARY_DIR}/nexus-dkms_${NEXUS_DEB_FILEVER}_all.deb
	${CMAKE_BINARY_DIR}/nexus-dkms_${NEXUS_DEB_FILEVER}.dsc
	${CMAKE_BINARY_DIR}/nexus-dkms_${NEXUS_DEB_FILEVER}_amd64.buildinfo
	${CMAKE_BINARY_DIR}/nexus-dkms_${NEXUS_DEB_FILEVER}.tar.gz
	${CMAKE_BINARY_DIR}/nexus-dkms_${NEXUS_DEB_FILEVER}_amd64.changes
	${CMAKE_CURRENT_SOURCE_DIR}/../debian/changelog
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
	# Older builds left behind get installed too: the image runs dpkg -i *.deb.
	COMMAND bash "-c" "rm -f ../nexus-dkms_* ${CMAKE_BINARY_DIR}/nexus-dkms_*"
	COMMAND ${CMAKE_COMMAND} -E copy "${NEXUS_CHANGELOG}" debian/changelog
	COMMAND bash "-c" "dpkg-buildpackage -uc -us"
	COMMAND bash "-c" "mv ../nexus-dkms_${NEXUS_DEB_FILEVER}* ${CMAKE_BINARY_DIR}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../"
)

set_property(
        TARGET nexus
        APPEND
        PROPERTY ADDITIONAL_CLEAN_FILES ${NEXUS_CLEAN_FILES}
)
