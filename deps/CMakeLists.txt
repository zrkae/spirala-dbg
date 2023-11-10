project(3rdparty_deps)

add_subdirectory(capstone-5.0.1)

set(CMAKE_C_FLAGS "-Wall -Wextra -fsanitize=address,undefined")

add_library(linenoise linenoise/linenoise.c)
target_include_directories(linenoise PUBLIC ${PROJECT_SOURCE_DIR}/linenoise)

add_subdirectory(zep)
