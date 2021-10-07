add_kernel_module(
  NAME mitm_snd
  SRCS mitm.c role.c sender.c
  MACROS MITM_ROLE=0)

add_kernel_module(
  NAME mitm_recv
  SRCS mitm.c role.c receiver.c
  MACROS MITM_ROLE=1)

add_kernel_module(
  NAME mitm_auth
  SRCS mitm.c role.c authenticator.c
  MACROS MITM_ROLE=2)
