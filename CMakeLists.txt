cmake_minimum_required(VERSION 3.5)
project(libtelnet
    VERSION 0.30.0
    LANGUAGES C
)
set(PROJECT_DESCRIPTION "TELNET protocol handling library")
set(PROJECT_HOMEPAGE_URL https://github.com/seanmiddleditch/libtelne)

add_library(libtelnet libtelnet.c)

add_compile_definitions(
    $<$<CXX_COMPILER_ID:MSVC>:-D_SCL_SECURE_NO_WARNINGS>
)

target_include_directories(libtelnet
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

add_subdirectory(util)
add_subdirectory(doc)
add_subdirectory(test)

include(GNUInstallDirs)

configure_file(libtelnet.pc.in libtelnet.pc)

install(TARGETS libtelnet
    EXPORT libtelnet-export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES libtelnet.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(EXPORT libtelnet-export
    FILE libtelnet.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libtelnet
)