project(spirala_dbg)

if (NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -pedantic -std=c++20 -fuse-ld=mold -fsanitize=address,undefined")

set(SOURCES
    main.cc
    repl.cc
    tracee.cc
    disassembly.cc
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
    linenoise
    zep
    capstone
)
