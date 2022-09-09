project("java_packages_extension")

add_subdirectory(libzip-1.7.3)

addOsqueryExtension(
  "${PROJECT_NAME}"
  java_packages.cpp
  java_package_utils.cpp
)
target_compile_options("${PROJECT_NAME}" PUBLIC -fPIC)
target_include_directories("${PROJECT_NAME}" PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/libzip-1.7.3" "${CMAKE_CURRENT_SOURCE_DIR}/libzip-1.7.3/lib")
link_directories("${CMAKE_CURRENT_BINARY_DIR}/libzip-1.7.3/lib")
target_link_libraries("${PROJECT_NAME}" PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/libzip-1.7.3/lib/libzip.a")
