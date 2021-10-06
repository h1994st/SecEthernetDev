#
# This module will set the following variables in your project
#
# WOLFSSL_FOUND
# WOLFSSL_INCLUDE_DIR
# WOLFSSL_LIBRARY
# WOLFSSL_VERSION_STRING

set(wolfssl_config_name wolfssl-config)
find_program(WOLFSSL_CONFIG
  ${wolfssl_config_name}
  DOC "Path to wolfssl-config tool.")

if (NOT WOLFSSL_CONFIG)
  if (NOT WOLFSSL_FIND_QUIETLY)
    _WOLFSSL_FAIL("No WolfSSL installation found.")
  endif ()
else ()
  macro(_WOLFSSL_FAIL _msg)
    if (WOLFSSL_FIND_REQUIRED)
      message(FATAL_ERROR "${_msg}")
    else ()
      if (NOT WOLFSSL_FIND_QUIETLY)
        message(WARNING "${_msg}")
      endif ()
    endif ()
  endmacro()

  macro(wolfssl_set var flag)
    set(result_code)
    execute_process(
      COMMAND ${WOLFSSL_CONFIG} --${flag}
      RESULT_VARIABLE result_code
      OUTPUT_VARIABLE WOLFSSL_${var}
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ${_quiet_arg}
    )
    if (result_code)
      _WOLFSSL_FAIL("Failed to execute llvm-config ('${WOLFSSL_CONFIG}', result code: '${result_code})'")
    else ()
      if (${ARGV2})
        file(TO_CMAKE_PATH "${WOLFSSL_${var}}" WOLFSSL_${var})
      endif ()
    endif ()
  endmacro()

  wolfssl_set(PREFIX_PATH prefix)

  # version
  wolfssl_set(VERSION version)

  # include
  set(WOLFSSL_INCLUDE_DIR "${WOLFSSL_PREFIX_PATH}/include")

  # lib
  set(WOLFSSL_LIBRARY "${WOLFSSL_PREFIX_PATH}/lib/libwolfssl.so")
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WolfSSL
  DEFAULT_MSG
  WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY WOLFSSL_VERSION)
mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY WOLFSSL_VERSION)
