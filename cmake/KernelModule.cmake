include(CMakeParseArguments)

#[[
add_kernel_module(NAME name
                  SRCS source1 [source2 ...]
                  MACROS macro1 [macro2 ...])

e.g.,
add_kernel_module(NAME foo
                  SRCS bar.c
                  MACROS DEBUG FOO=1 BAR="foo")
]]

# TODO: Support debug mode

if (NOT LKM_DIR)
  message(FATAL_ERROR "Please set up LKM_DIR to the Linux Kernel header source directory!")
endif ()

if (NOT LKM_INCLUDE_DIRS)
  message(FATAL_ERROR "Please set up LKM_INCLUDE_DIRS to the Linux Kernel header directories!")
endif ()

function(add_kernel_module)
  set(options)
  set(one_value_args NAME)
  set(multi_value_args SRCS MACROS)
  cmake_parse_arguments(LKM_TARGET "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})
  if (NOT LKM_TARGET_NAME)
    message(FATAL_ERROR "Target name is missing!")
  endif ()
  if ("${LKM_TARGET_NAME}.c" IN_LIST LKM_TARGET_SRCS)
    message(FATAL_ERROR "The target name of the kernel module is the same as one of source files!")
  endif ()

  list(TRANSFORM LKM_TARGET_MACROS
    PREPEND "-D"
    OUTPUT_VARIABLE _cflags)
  string(REPLACE ";" " " _cflags_str "${_cflags}")

  # Prepare the absolute path to source files
  list(TRANSFORM LKM_TARGET_SRCS
    PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/"
    OUTPUT_VARIABLE LKM_TARGET_SRC_PATHS)

  # Prepare the absolute path to byproducts
  list(TRANSFORM LKM_TARGET_SRCS
    # Remove file extensions
    REPLACE "\\.c$" ""
    OUTPUT_VARIABLE _src_names)
  set(_all_src_names ${_src_names})
  list(APPEND _all_src_names "${LKM_TARGET_NAME}" "${LKM_TARGET_NAME}.mod")
  # object files
  list(TRANSFORM _all_src_names
    APPEND ".o"
    OUTPUT_VARIABLE _byproducts_o)
  # .cmd files
  list(TRANSFORM _byproducts_o
    APPEND ".cmd"
    OUTPUT_VARIABLE _byproducts_cmd)
  # .cmd files are hidden
  list(TRANSFORM _byproducts_cmd
    PREPEND "."
    OUTPUT_VARIABLE _byproducts_cmd)
  # Merge object files and .cmd files
  set(_byproducts ${_byproducts_o})
  list(APPEND _byproducts ${_byproducts_cmd})
  # Add other generated files
  list(APPEND _byproducts ".${LKM_TARGET_NAME}.ko.cmd" ".${LKM_TARGET_NAME}.mod.cmd")
  list(APPEND _byproducts "${LKM_TARGET_NAME}.mod" "${LKM_TARGET_NAME}.mod.c")
  list(APPEND _byproducts "Module.symvers" "modules.order")
  # Add path prefix
  list(TRANSFORM _byproducts
    PREPEND "${CMAKE_CURRENT_BINARY_DIR}/"
    OUTPUT_VARIABLE LKM_TARGET_BYPRODUCTS)
  # The Kbuild file is also a byproduct
  list(APPEND LKM_TARGET_BYPRODUCTS "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild")

  set(KBUILD_CMD
    $(MAKE) -C ${LKM_DIR} modules
    M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR}
    EXTRA_CFLAGS='${_cflags_str}')
  set(LKM_FILE ${LKM_TARGET_NAME}.ko)
  set(LKM_KBUILD_FILE ${LKM_TARGET_NAME}_Kbuild)

  list(TRANSFORM _src_names
    APPEND ".o"
    OUTPUT_VARIABLE _objs)
  string(REPLACE ";" " " _objs_str "${_objs}")

  add_custom_target(${LKM_TARGET_NAME} ALL
    DEPENDS ${LKM_FILE}
    SOURCES ${LKM_TARGET_SRC_PATHS})
  add_custom_command(
    OUTPUT ${LKM_FILE}
    # Generate the Kbuild file
    COMMAND rm -f ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
    COMMAND touch ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
    COMMAND echo "obj-m := ${LKM_TARGET_NAME}.o" >> ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
    COMMAND echo "${LKM_TARGET_NAME}-objs := ${_objs_str}" >> ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
    # Build the kernel module
    COMMAND ${KBUILD_CMD}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${LKM_TARGET_SRC_PATHS}
    BYPRODUCTS ${LKM_TARGET_BYPRODUCTS}
    COMMENT "Building ${LKM_FILE}")

  # Add a dummy target for CLion IDE
  set(LKM_DUMMY_TARGET ${LKM_TARGET_NAME}_dummy)
  add_library(${LKM_DUMMY_TARGET}
    ${LKM_TARGET_SRCS})
  target_include_directories(${LKM_DUMMY_TARGET}
    PRIVATE ${LKM_INCLUDE_DIRS})
  target_compile_definitions(${LKM_DUMMY_TARGET}
    # Find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
    PRIVATE __KERNEL__ MODULE
    # `netdev_dbg` depends on `KBUILD_MODNAME`
    PRIVATE KBUILD_MODNAME="${LKM_TARGET_NAME}"
    PRIVATE ${LKM_TARGET_MACROS})
  target_compile_options(${LKM_DUMMY_TARGET}
    PRIVATE -include ${LKM_DIR}/include/linux/kconfig.h
    PRIVATE -include ${LKM_DIR}/include/linux/compiler_types.h)
  set_property(
    TARGET ${LKM_DUMMY_TARGET}
    PROPERTY C_STANDARD 90)
endfunction()
