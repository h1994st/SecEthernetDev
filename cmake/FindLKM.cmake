#
# This module will set the following variables in your project
#
# LKM_FOUND
# LKM_DIR
# LKM_INCLUDE_DIR
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
set(LKM_INCLUDE_DIR ${LKM_DIR}/include)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LKM
  DEFAULT_MSG
  LKM_DIR LKM_INCLUDE_DIR LKM_RELEASE)
mark_as_advanced(LKM_DIR LKM_INCLUDE_DIR LKM_RELEASE)
