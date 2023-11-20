#include <iostream>
#include <signal.h>

#include "repl.hpp"
#include "tracee.hpp"

void setup()
{
    struct sigaction act; 
    act.sa_handler = SIG_IGN;
    sigaction(SIGINT, &act, nullptr);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "Error: not enough arguments\n";
        std::exit(1);
    }
    setup();

    Tracee dbg { argv[1] };
    repl::start(dbg);

    return 0;
}
