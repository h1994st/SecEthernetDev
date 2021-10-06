#
# This module will set the following variables in your project
#
# LKM_FOUND
# LKM_DIR
# LKM_INCLUDE_DIRS
# LKM_RELEASE
# (LKM: Linux Kernel Module)
#
# References:
# [1] https://musteresel.github.io/posts/2020/02/cmake-template-linux-kernel-module.html
# [2] https://gitlab.com/christophacham/cmake-kernel-module/-/tree/master
# [3] https://gitlab.com/phip1611/cmake-kernel-module
# [4] https://github.com/enginning/cmake-kernel-module


# Find the kernel release
execute_process(
  COMMAND uname -r
  OUTPUT_VARIABLE LKM_RELEASE
  OUTPUT_STRIP_TRAILING_WHITESPACE)

# Find the headers
find_path(LKM_DIR
  include/linux/user.h
  PATHS /lib/modules/${LKM_RELEASE}/build
  REQUIRED)

# Find the architecture
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
  set(_arch "x86")
else ()
  message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif ()

#[[
  -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include
  -I./arch/x86/include
  -I./arch/x86/include/generated
  -I./include
  -I./arch/x86/include/uapi
  -I./arch/x86/include/generated/uapi
  -I./include/uapi
  -I./include/generated/uapi
  -include ./include/linux/kconfig.h
  -Iubuntu/include
  -include ./include/linux/compiler_types.h
]]
set(LKM_INCLUDE_DIRS
  ${LKM_DIR}/arch/${_arch}/include
  ${LKM_DIR}/arch/${_arch}/include/generated
  ${LKM_DIR}/include
  ${LKM_DIR}/arch/${_arch}/include/uapi
  ${LKM_DIR}/arch/${_arch}/include/generated/uapi
  ${LKM_DIR}/include/uapi
  ${LKM_DIR}/include/generated/uapi
  ${LKM_DIR}/ubuntu/include)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LKM
  DEFAULT_MSG
  LKM_DIR LKM_INCLUDE_DIRS LKM_RELEASE)
mark_as_advanced(LKM_DIR LKM_INCLUDE_DIRS LKM_RELEASE)
