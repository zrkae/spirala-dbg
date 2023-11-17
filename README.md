# spirala
spirala is a linux user space program debugger. It works with the ELF file format and the x86-64 architecture, with plans to support
32 bit and ARM architectures.

### Features
- breakpoints, setting registers, etc. all the basic debugger stuff
- elf parser backend - listing symbols, functions
- [capstone](http://www.capstone-engine.org/) integration - disassemble functions, memory regions

### Get started
#### dependencies
- Required external libraries: `capstone`
- A c++20 compliant compiler
- The rest of dependencies are provided in the tree itself.

#### clone
```
git clone --recursive 'https://github.com/zrkae/spirala_dbg'
```

#### build
```
meson setup build
cd build
ninja
```
