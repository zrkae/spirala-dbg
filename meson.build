project('spirala-dbg', 'cpp',
        default_options: ['cpp_std=c++20',
                          'warning_level=3'])

deps = [dependency('capstone')]

subproj_names = ['zep', 'linenoise']
foreach name : subproj_names
        subproj = subproject(name) 
        deps += subproj.get_variable(name + '_dep')
endforeach

subdir('src')
