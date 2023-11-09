# spirala
spirala is a linux user space program debugger. It works with the ELF file format and the x86-64 architecture, with plans to support
32 bit and ARM architectures.

### build
You will need a linux system with a c++20 compliant compiler.

```
cmake -B build
cmake --build build -j<thread_count>
```
