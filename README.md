# spirala
spirala is a linux user space program debugger. It works with the ELF file format and the x86-64 architecture, with plans to support
32 bit and ARM architectures.

### Features
- breakpoints, setting registers, etc. all the basic debugger stuff
- elf parser backend - listing symbols, functions
- [capstone](http://www.capstone-engine.org/) integration - disassemble functions, memory regions

### build
You will need a linux system with a c++20 compliant compiler.
All the dependencies are already provided in the tree. (some as submodules)

##### clone
```
git clone --recursive 'https://github.com/zrkae/spirala_dbg'
```

```
cmake -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_X86_SUPPORT=ON -B build
cmake --build build -j<thread_count>
```
