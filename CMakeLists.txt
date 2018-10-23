cmake_minimum_required(VERSION 3.5)
project(irods_rule_engine_plugin-update_collection_timestamp)

find_package(IRODS 4.2.5 EXACT REQUIRED CONFIG)

set(CMAKE_C_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang)
set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)

include(${IRODS_TARGETS_PATH})

set(CMAKE_COMPILE_COMMANDS TRUE)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_INSTALL_RPATH ${IRODS_EXTERNALS_FULLPATH_CLANG_RUNTIME}/lib)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")

set(PLUGIN irods-rule-engine-plugin-update-collection-timestamp)

add_library(${PLUGIN} MODULE ${CMAKE_SOURCE_DIR}/src/libirods_rule_engine_plugin-update_collection_timestamp.cpp)
set_property(TARGET ${PLUGIN} PROPERTY CXX_STANDARD ${IRODS_CXX_STANDARD})
target_compile_options(${PLUGIN} PRIVATE -Wno-write-strings)
target_compile_definitions(${PLUGIN} PRIVATE ${IRODS_COMPILE_DEFINITIONS} BOOST_SYSTEM_NO_DEPRECATED)
target_include_directories(${PLUGIN} PRIVATE ${IRODS_INCLUDE_DIRS}
                                             ${IRODS_EXTERNALS_FULLPATH_CLANG}/include/c++/v1
                                             ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)
target_link_libraries(${PLUGIN} PRIVATE irods_server
                                        irods_common
                                        ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so
                                        ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so
                                        dl)

#install(TARGETS ${PLUGIN} LIBRARY DESTINATION ${IRODS_PLUGINS_DIRECTORY}/rule_engines)
install(TARGETS ${PLUGIN} LIBRARY DESTINATION lib/irods/plugins/rule_engines)

set(IRODS_PLUGIN_VERSION_MAJOR 1)
set(IRODS_PLUGIN_VERSION_MINOR 0)
set(IRODS_PLUGIN_VERSION_PATCH 0)
set(IRODS_PLUGIN_VERSION "${IRODS_PLUGIN_VERSION_MAJOR}.${IRODS_PLUGIN_VERSION_MINOR}.${IRODS_PLUGIN_VERSION_PATCH}")

set(CPACK_PACKAGE_FILE_NAME "irods-rule-engine-plugin-update-collection-timestamp-${IRODS_PLUGIN_VERSION}-${IRODS_LINUX_DISTRIBUTION_NAME}${IRODS_LINUX_DISTRIBUTION_VERSION_MAJOR}-${CMAKE_SYSTEM_PROCESSOR}")

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_VERSION ${IRODS_PLUGIN_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${IRODS_PLUGIN_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${IRODS_PLUGIN_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${IRODS_PLUGIN_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT "Renaissance Computing Institute <info@irods.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")
set(CPACK_PACKAGE_VENDOR "Renaissance Computing Institute <info@irods.org>")

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SECTION "contrib/science")
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://irods.org")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_VENDOR "iRODS Consortium")
set(CPACK_RPM_PACKAGE_URL "https://irods.org")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME "irods-rule-engine-plugin-update-collection-timestamp")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server (= ${IRODS_VERSION}), irods-runtime (= ${IRODS_VERSION}), libc6")

set(CPACK_RPM_PACKAGE_NAME "irods-rule-engine-plugin-update-collection-timestamp")
if (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos" OR IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos linux")
  set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}, openssl")
elseif (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "opensuse")
    set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}, libopenssl1_0_0")
endif()

if (NOT CPACK_GENERATOR)
    set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
    message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)
