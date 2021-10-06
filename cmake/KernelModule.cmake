include(CMakeParseArguments)

#[[
add_kernel_module(NAME name
                  SRCS source1 [source2 ...])
]]

# TODO:
# - Support user-defined envs
# - Support debug mode

if (NOT LKM_DIR)
  message(FATAL_ERROR "Please set up LKM_DIR to the Linux Kernel header directory!")
endif ()

function(add_kernel_module)
  set(options)
  set(one_value_args NAME)
  set(multi_value_args SRCS)
  cmake_parse_arguments(LKM_TARGET "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})
  if (NOT LKM_TARGET_NAME)
    message(FATAL_ERROR "Target name is missing!")
  endif ()
  if ("${LKM_TARGET_NAME}.c" IN_LIST LKM_TARGET_SRCS)
    message(FATAL_ERROR "The target name of the kernel module is the same as one of source files!")
  endif ()

  # Prepare the absolute path to source files
  list(TRANSFORM LKM_TARGET_SRCS
    PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/"
    OUTPUT_VARIABLE LKM_TARGET_SRC_PATHS)

  # Prepare the absolute path to byproducts
  list(TRANSFORM LKM_TARGET_SRCS
    # Remove file extensions
    REPLACE \.c$ ""
    OUTPUT_VARIABLE _src_names)
  set(_all_src_names ${_src_names})
  list(APPEND _all_src_names "${LKM_TARGET_NAME}" "${LKM_TARGET_NAME}.mod")
  list(TRANSFORM _all_src_names
    APPEND ".o"
    OUTPUT_VARIABLE _byproducts_o)
  list(TRANSFORM _byproducts_o
    APPEND ".cmd"
    OUTPUT_VARIABLE _byproducts_cmd)
  list(TRANSFORM _byproducts_cmd
    PREPEND "."
    OUTPUT_VARIABLE _byproducts_cmd)
  set(_byproducts ${_byproducts_o})
  list(APPEND _byproducts ${_byproducts_cmd})
  list(APPEND _byproducts ".${LKM_TARGET_NAME}.ko.cmd" ".${LKM_TARGET_NAME}.mod.cmd")
  list(APPEND _byproducts "${LKM_TARGET_NAME}.mod" "${LKM_TARGET_NAME}.mod.c")
  list(APPEND _byproducts "Module.symvers" "modules.order")
  list(TRANSFORM _byproducts
    PREPEND "${CMAKE_CURRENT_BINARY_DIR}/"
    OUTPUT_VARIABLE LKM_TARGET_BYPRODUCTS)
  # The Kbuild file is temporary
  list(APPEND LKM_TARGET_BYPRODUCTS "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild")

  set(KBUILD_CMD $(MAKE) -C ${LKM_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})
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
endfunction()
