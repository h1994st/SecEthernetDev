set(MPI_SRCS
  mpi/mpiutil.c
  mpi/mpicoder.c
  mpi/mpi-mod.c
  mpi/mpi-cmp.c
  mpi/mpi-sub-ui.c
  mpi/mpi-bit.c
  mpi/mpi-add.c
  mpi/mpi-mul.c
  mpi/mpi-div.c
  mpi/mpi-inv.c
  mpi/generic_mpih-add1.c
  mpi/generic_mpih-lshift.c
  mpi/generic_mpih-mul1.c
  mpi/generic_mpih-mul2.c
  mpi/generic_mpih-mul3.c
  mpi/generic_mpih-rshift.c
  mpi/generic_mpih-sub1.c
  mpi/mpih-cmp.c
  mpi/mpih-div.c
  mpi/mpih-mul.c)

# Force CMake to create `mpi` library
add_subdirectory(mpi)

set(TIME_LOCK_PUZZLE_SRCS
  time_lock_puzzle.c)

set(COMMON_SRCS
  mitm.c role.c
  ${MPI_SRCS}
  ${TIME_LOCK_PUZZLE_SRCS})

add_kernel_module(
  NAME mitm_snd
  SRCS ${COMMON_SRCS} sender.c
  MACROS MITM_ROLE=0)

add_kernel_module(
  NAME mitm_recv
  SRCS ${COMMON_SRCS} receiver.c
  MACROS MITM_ROLE=1)

add_kernel_module(
  NAME mitm_auth
  SRCS ${COMMON_SRCS} authenticator.c
  MACROS MITM_ROLE=2)

add_kernel_module(
  NAME mitm_auth_rsa
  SRCS ${COMMON_SRCS} authenticator_rsa.c
  MACROS MITM_AUTH_RSA MITM_ROLE=2)

add_kernel_module(
  NAME mitm_recv_dos
  SRCS ${COMMON_SRCS} receiver_dos.c
  MACROS MITM_ROLE=1 MITM_DOS_PROTECTION)
