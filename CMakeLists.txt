cmake_minimum_required(VERSION 3.5)
project(libtelnet VERSION 0.30.0 LANGUAGES C)

add_library(libtelnet libtelnet.c)

target_include_directories(libtelnet
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

include(GNUInstallDirs)
install(TARGETS libtelnet
    EXPORT libtelnet-export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(EXPORT libtelnet-export
    FILE libtelnet.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libtelnet
)