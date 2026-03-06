# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(unixsock_library VERSION 0.0.1 LANGUAGES C)

add_library(unixsock SHARED
  "unixsock.c"
)

set_target_properties(unixsock PROPERTIES
  PUBLIC_HEADER unixsock.h
  OUTPUT_NAME "unixsock"
)

target_compile_definitions(unixsock PUBLIC DART_SHARED_LIB)

if (ANDROID)
  # Support Android 15 16k page size.
  target_link_options(unixsock PRIVATE "-Wl,-z,max-page-size=16384")
endif()
