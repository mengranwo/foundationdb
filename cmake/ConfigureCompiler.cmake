set(USE_GPERFTOOLS OFF CACHE BOOL "Use gperfools for profiling")
set(USE_VALGRIND OFF CACHE BOOL "Compile for valgrind usage")
set(USE_VALGRIND_FOR_CTEST ${USE_VALGRIND} CACHE BOOL "Use valgrind for ctest")
set(ALLOC_INSTRUMENTATION OFF CACHE BOOL "Instrument alloc")
set(WITH_UNDODB OFF CACHE BOOL "Use rr or undodb")
set(USE_ASAN OFF CACHE BOOL "Compile with address sanitizer")
set(USE_UBSAN OFF CACHE BOOL "Compile with undefined behavior sanitizer")
set(FDB_RELEASE OFF CACHE BOOL "This is a building of a final release")
set(USE_LD "DEFAULT" CACHE STRING "The linker to use for building: can be LD (system default, default choice), BFD, GOLD, or LLD")
set(USE_LIBCXX OFF CACHE BOOL "Use libc++")
set(USE_CCACHE OFF CACHE BOOL "Use ccache for compilation if available")
set(RELATIVE_DEBUG_PATHS OFF CACHE BOOL "Use relative file paths in debug info")
set(STATIC_LINK_LIBCXX ON CACHE BOOL "Statically link libstdcpp/libc++")

set(rel_debug_paths OFF)
if(RELATIVE_DEBUG_PATHS)
  set(rel_debug_paths ON)
endif()

if(USE_GPERFTOOLS)
  find_package(Gperftools REQUIRED)
endif()

add_compile_options(-DCMAKE_BUILD)
add_compile_definitions(BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_DEPRECATED)

find_package(Threads REQUIRED)
if(ALLOC_INSTRUMENTATION)
  add_compile_options(-DALLOC_INSTRUMENTATION)
endif()
if(WITH_UNDODB)
  add_compile_options(-DWITH_UNDODB)
endif()
if(DEBUG_TASKS)
  add_compile_options(-DDEBUG_TASKS)
endif()

if(NDEBUG)
  add_compile_options(-DNDEBUG)
endif()

if(FDB_RELEASE)
  add_compile_options(-DFDB_RELEASE)
endif()

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
if (NOT OPEN_FOR_IDE)
  add_definitions(-DNO_INTELLISENSE)
endif()
if(WIN32)
  add_definitions(-DUSE_USEFIBERS)
else()
  add_definitions(-DUSE_UCONTEXT)
endif()

if ((NOT USE_CCACHE) AND (NOT "$ENV{USE_CCACHE}" STREQUAL ""))
	string(TOUPPER "$ENV{USE_CCACHE}" USE_CCACHEENV)
	if (("${USE_CCACHEENV}" STREQUAL "ON") OR ("${USE_CCACHEENV}" STREQUAL "1") OR ("${USE_CCACHEENV}" STREQUAL "YES"))
		set(USE_CCACHE ON)
	endif()
endif()
if (USE_CCACHE)
	FIND_PROGRAM(CCACHE_FOUND "ccache")
	if(CCACHE_FOUND)
		set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
		set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
	else()
		message(SEND_ERROR "CCACHE is ON, but ccache was not found")
	endif()
endif()

if ((NOT USE_LIBCXX) AND (NOT "$ENV{USE_LIBCXX}" STREQUAL ""))
	string(TOUPPER "$ENV{USE_LIBCXX}" USE_LIBCXXENV)
	if (("${USE_LIBCXXENV}" STREQUAL "ON") OR ("${USE_LIBCXXENV}" STREQUAL "1") OR ("${USE_LIBCXXENV}" STREQUAL "YES"))
		set(USE_LIBCXX ON)
	endif()
endif()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_INCLUDES stdlib.h malloc.h)
set(CMAKE_REQUIRED_LIBRARIES c)
set(CMAKE_CXX_STANDARD 17)

if(WIN32)
  # see: https://docs.microsoft.com/en-us/windows/desktop/WinProg/using-the-windows-headers
  # this sets the windows target version to Windows 7
  set(WINDOWS_TARGET 0x0601)
  add_compile_options(/W3 /EHsc /bigobj $<$<CONFIG:Release>:/Zi> /MP)
  add_compile_definitions(_WIN32_WINNT=${WINDOWS_TARGET} BOOST_ALL_NO_LIB)
else()
  set(GCC NO)
  set(CLANG NO)
  if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
    set(CLANG YES)
  else()
    # This is not a very good test. However, as we do not really support many architectures
    # this is good enough for now
    set(GCC YES)
  endif()

  # Use the linker environmental variable, if specified and valid
  if ((USE_LD STREQUAL "DEFAULT") AND (NOT "$ENV{USE_LD}" STREQUAL ""))
    string(TOUPPER "$ENV{USE_LD}" USE_LDENV)
    if (("${USE_LDENV}" STREQUAL "LD") OR ("${USE_LDENV}" STREQUAL "GOLD") OR ("${USE_LDENV}" STREQUAL "LLD") OR ("${USE_LDENV}" STREQUAL "BFD") OR ("${USE_LDENV}" STREQUAL "DEFAULT"))
      set(USE_LD "${USE_LDENV}")
    else()
      message (FATAL_ERROR "USE_LD must be set to DEFAULT, LD, BFD, GOLD, or LLD!")
    endif()
  endif()

  # check linker flags.
  if (USE_LD STREQUAL "DEFAULT")
    set(USE_LD "LD")
  else()
    if ((NOT (USE_LD STREQUAL "LD")) AND (NOT (USE_LD STREQUAL "GOLD")) AND (NOT (USE_LD STREQUAL "LLD")) AND (NOT (USE_LD STREQUAL "BFD")))
      message (FATAL_ERROR "USE_LD must be set to DEFAULT, LD, BFD, GOLD, or LLD!")
    endif()
  endif()

  # if USE_LD=LD, then we don't do anything, defaulting to whatever system
  # linker is available (e.g. binutils doesn't normally exist on macOS, so this
  # implies the default xcode linker, and other distros may choose others by
  # default).

  if(USE_LD STREQUAL "BFD")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=bfd -Wl,--disable-new-dtags")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=bfd -Wl,--disable-new-dtags")
  endif()

  if(USE_LD STREQUAL "GOLD")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold -Wl,--disable-new-dtags")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold -Wl,--disable-new-dtags")
  endif()

  if(USE_LD STREQUAL "LLD")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld -Wl,--disable-new-dtags")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld -Wl,--disable-new-dtags")
  endif()

  if(rel_debug_paths)
    add_compile_options("-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=." "-fdebug-prefix-map=${CMAKE_BINARY_DIR}=.")
  endif()

  # we always compile with debug symbols. CPack will strip them out
  # and create a debuginfo rpm
  add_compile_options(-ggdb -fno-omit-frame-pointer)
  if(USE_ASAN)
    add_compile_options(
      -fsanitize=address
      -DUSE_SANITIZER)
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS}    -fsanitize=address ${CMAKE_THREAD_LIBS_INIT}")
  endif()

  if(USE_UBSAN)
    add_compile_options(
      -fsanitize=undefined
      -DUSE_SANITIZER)
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=undefined")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=undefined")
    set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS}    -fsanitize=undefined ${CMAKE_THREAD_LIBS_INIT}")
  endif()

  if(PORTABLE_BINARY)
    message(STATUS "Create a more portable binary")
    set(CMAKE_MODULE_LINKER_FLAGS "-static-libstdc++ -static-libgcc ${CMAKE_MODULE_LINKER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "-static-libstdc++ -static-libgcc ${CMAKE_SHARED_LINKER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS    "-static-libstdc++ -static-libgcc ${CMAKE_EXE_LINKER_FLAGS}")
  endif()
  if(STATIC_LINK_LIBCXX)
    if (NOT USE_LIBCXX AND NOT APPLE)
      add_link_options(-static-libstdc++ -static-libgcc)
    endif()
  endif()
  # Instruction sets we require to be supported by the CPU
  add_compile_options(
    -maes
    -mmmx
    -mavx
    -msse4.2)

  if (USE_VALGRIND)
    add_compile_options(-DVALGRIND -DUSE_VALGRIND)
  endif()
  if (CLANG)
    add_compile_options()
    if (APPLE OR USE_LIBCXX)
      add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)
      add_compile_definitions(WITH_LIBCXX)
      if (NOT APPLE)
        add_link_options(-lc++ -lc++abi -Wl,-build-id=sha1)
      endif()
    endif()
    if (OPEN_FOR_IDE)
      add_compile_options(
        -Wno-unknown-attributes)
    endif()
    add_compile_options(
      -Wno-unknown-warning-option
      -Wno-dangling-else
      -Wno-sign-compare
      -Wno-comment
      -Wno-unknown-pragmas
      -Wno-delete-non-virtual-dtor
      -Wno-undefined-var-template
      -Wno-tautological-pointer-compare
      -Wno-format)
    if (USE_CCACHE)
      add_compile_options(
        -Wno-register
        -Wno-error=unused-command-line-argument)
    endif()
  endif()
  if (CMAKE_GENERATOR STREQUAL Xcode)
  else()
    add_compile_options(-Werror)
  endif()
  if (GCC)
    add_compile_options(-Wno-pragmas)

    # Otherwise `state [[maybe_unused]] int x;` will issue a warning.
    # https://stackoverflow.com/questions/50646334/maybe-unused-on-member-variable-gcc-warns-incorrectly-that-attribute-is
    add_compile_options(-Wno-attributes)
  endif()
  add_compile_options(-Wno-error=format
    -Wunused-variable
    -Wno-deprecated
    -fvisibility=hidden
    -Wreturn-type
    -fPIC)
  if (GPERFTOOLS_FOUND AND GCC)
    add_compile_options(
      -fno-builtin-malloc
      -fno-builtin-calloc
      -fno-builtin-realloc
      -fno-builtin-free)
  endif()

  # Check whether we can use dtrace probes
  include(CheckSymbolExists)
  check_symbol_exists(DTRACE_PROBE sys/sdt.h SUPPORT_DTRACE)
  check_symbol_exists(aligned_alloc stdlib.h HAS_ALIGNED_ALLOC)
  message(STATUS "Has aligned_alloc: ${HAS_ALIGNED_ALLOC}")
  if(SUPPORT_DTRACE)
    add_compile_definitions(DTRACE_PROBES)
  endif()
  if(HAS_ALIGNED_ALLOC)
    add_compile_definitions(HAS_ALIGNED_ALLOC)
  endif()

  if(CMAKE_COMPILER_IS_GNUCXX)
    set(USE_LTO OFF CACHE BOOL "Do link time optimization")
    if (USE_LTO)
      add_compile_options($<$<CONFIG:Release>:-flto>)
      set(CMAKE_AR  "gcc-ar")
      set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
      set(CMAKE_C_ARCHIVE_FINISH   true)
      set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
      set(CMAKE_CXX_ARCHIVE_FINISH   true)
    endif()
  endif()
endif()
