project('linenoise', 'c')

sources = ['linenoise.c']
inc = include_directories('.')

slib_linenoise = static_library('linenoise', sources, include_directories: inc)

linenoise_dep = declare_dependency(include_directories : inc, link_with: slib_linenoise)
