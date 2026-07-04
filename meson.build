# Set up a C and C++ project with useful defaults for debugging
project(
  'slipstream',
  ['c', 'cpp'],
  version: '0.1.0',
  license: 'Apache-2.0',
  meson_version: '>=1.0.0',
  default_options: [
    'optimization=s',
    'debug=false',
    'b_ndebug=true',
    'cpp_rtti=false',
    'strip=true',
    'cpp_std=gnu++11',
    'c_std=gnu11',
    'default_library=shared',
    'warning_level=everything',
    'b_lto=true'
  ],
)

if host_machine.system() != 'android' and host_machine.system() != 'darwin'
  add_project_link_arguments('-fuse-ld=mold', language: ['c', 'cpp'])
endif

# Hide internal symbols and allow aggressive dead-code elimination
add_project_arguments(
  '-fvisibility=hidden',
  '-ffunction-sections',
  '-fdata-sections',
  '-fno-unwind-tables',
  '-fno-asynchronous-unwind-tables',
  '-fmerge-all-constants',
  language: ['c', 'cpp']
)

# Aliases to significant locations in the source tree
src = 'src'
extern = 'extern'
lua_resty = extern / 'lua-resty-base-encoding'
quick_args = extern / 'quick_arg_parser'
spcdns = extern / 'SPCDNS' / src

# Sources common to both client and server
common_sources = files(
  src / 'slipstream_sockloop.c',
  src / 'slipstream_utils.c',
  src / 'slipstream_inline_dots.c',
  lua_resty / 'base32.c',
  spcdns / 'codec.c',
  spcdns / 'mappings.c',
  spcdns / 'netsimple.c',
  spcdns / 'output.c',
)

# Various directories with headers for the sources
include_dirs = include_directories('include', extern, quick_args, spcdns, lua_resty)

# Default linker arguments
link_args = ['-Wl,-s', '-Wl,--icf=all', '-Wl,--hash-style=gnu', '-Wl,--gc-sections']

# Set up static links
is_static = get_option('default_library') == 'static'
if is_static and host_machine.system() != 'darwin'
  link_args += [
    '-static-libgcc',
    '-static-libstdc++',
  ]
endif

# Import the CMake module
cmake = import('cmake')
fs = import('fs')

# Get the cmake options objects
picoquic_opts = cmake.subproject_options()

# Add necessary CMake defines
picotls_source_dir = meson.project_source_root() / 'subprojects' / 'picoquic' / 'picotls'
picoquic_release_c_flags = '-Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants'
picoquic_cmake_defines = [
  {'CMAKE_INTERPROCEDURAL_OPTIMIZATION': 'ON'},
  {'PICOQUIC_FETCH_PTLS': 'ON'},
  {'BUILD_HTTP': 'OFF'},
  {'ENABLE_ASAN': 'OFF'},
  {'ENABLE_UBSAN': 'OFF'},
  {'CMAKE_POLICY_VERSION_MINIMUM': '3.5'},
  {'BUILD_DEMO': 'OFF'},
  {'BUILD_TESTING': 'OFF'},
]

if fs.exists(picotls_source_dir / 'CMakeLists.txt') and fs.exists(picotls_source_dir / 'deps' / 'picotest' / 'picotest.c')
  picotls_include_arg = '-I' + (picotls_source_dir / 'include')
  picoquic_cmake_defines += [{'CMAKE_C_FLAGS': picotls_include_arg}]
  picoquic_release_c_flags += ' ' + picotls_include_arg
  picoquic_cmake_defines += [{'FETCHCONTENT_SOURCE_DIR_PICOTLS': picotls_source_dir}]
endif

picoquic_cmake_defines += [{'CMAKE_C_FLAGS_RELEASE': picoquic_release_c_flags}]

if get_option('static_openssl')
  picoquic_cmake_defines += [{'OPENSSL_USE_STATIC_LIBS': 'TRUE'}]
endif

openssl_root_dir = get_option('openssl_root_dir')
if openssl_root_dir != ''
  picoquic_cmake_defines += [{'OPENSSL_ROOT_DIR': openssl_root_dir}]
endif

picoquic_opts.add_cmake_defines(
  picoquic_cmake_defines,
)
# Configure picoquic debug printing
if get_option('buildtype').startswith('debug')
  picoquic_opts.add_cmake_defines(
    {'DISABLE_DEBUG_PRINTF': 'OFF'},
  )
else
  picoquic_opts.add_cmake_defines(
    {'DISABLE_DEBUG_PRINTF': 'ON'},
  )
endif
# Configure optional picoquic logging
loglib_enabled = get_option('build_loglib')
if loglib_enabled
  picoquic_opts.add_cmake_defines(
    {'BUILD_LOGREADER': 'ON'},
  )
  add_project_arguments('-DBUILD_LOGLIB', language: ['c', 'cpp'])
else
  picoquic_opts.add_cmake_defines(
    {'BUILD_LOGREADER': 'OFF'},
  )
endif

# Reference picoquic as a CMake subproject
picoquic_proj = cmake.subproject(
  'picoquic',
  options: picoquic_opts,
)

# Dependencies used by both executables
slipstream_cli_deps = [
  dependency('threads'), # for picoquic
  picoquic_proj.dependency('picoquic-core'),
]
# Link optional picoquic logging
if loglib_enabled
  slipstream_cli_deps += picoquic_proj.dependency('picoquic-log')
endif

# Sources only used by client
client_sources = files(
  src / 'slipstream_client.c',
  src / 'slipstream_client_cli.cpp',
)

# Sources only used by server
server_sources = files(
  src / 'slipstream_server.c',
  src / 'slipstream_server_cc.c',
  src / 'slipstream_server_cli.cpp',
)

# The final client executable
executable(
  'slipstream-client',
  client_sources + common_sources,
  dependencies: slipstream_cli_deps,
  include_directories: include_dirs,
  link_args: link_args,
  build_by_default: true,
)

# The final server executable
executable(
  'slipstream-server',
  server_sources + common_sources,
  dependencies: slipstream_cli_deps,
  include_directories: include_dirs,
  link_args: link_args,
  build_by_default: true,
)
