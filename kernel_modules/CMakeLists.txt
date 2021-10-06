include_directories(${LKM_INCLUDE_DIR})

add_kernel_module(
  NAME mitm_snd
  SRCS mitm.c role.c sender.c)
