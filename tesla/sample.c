#include "sample.h"

void printbuf(char *s, int slen) {
  int i;
  for (i = 0; i < slen; i++) { printf("%.2x", s[i]); }
  printf("\n");
}
#ifdef WIN32
#include <windows.h>
#include <winsock.h>

void handle_error(void) {
  /*
   * Errors are handled by calling the WSAGetLastError routine which
   * will return the last error as one of the following. 
   */

  switch (WSAGetLastError()) {
    case WSANOTINITIALISED: printf("Unable to initialise socket.\n"); break;

    case WSAEAFNOSUPPORT:
      printf("The specified address family is not supported.\n");
      break;

    case WSAEADDRNOTAVAIL:
      printf("Specified address is not available from the local machine.\n");
      break;

    case WSAECONNREFUSED:
      printf("The attempt to connect was forcefully rejected.\n");
      break;

    case WSAEDESTADDRREQ:
      printf("address destination address is required.\n");
      break;

    case WSAEFAULT: printf("The namelen argument is incorrect.\n"); break;

    case WSAEINVAL:
      printf("The socket is not already bound to an address.\n");
      break;

    case WSAEISCONN: printf("The socket is already connected.\n"); break;

    case WSAEADDRINUSE:
      printf("The specified address is already in use.\n");
      break;

    case WSAEMFILE: printf("No more file descriptors are available.\n"); break;

    case WSAENOBUFS:
      printf("No buffer space available. The socket cannot be created.\n");
      break;

    case WSAEPROTONOSUPPORT:
      printf("The specified protocol is not supported.\n");
      break;

    case WSAEPROTOTYPE:
      printf("The specified protocol is the wrong type for this socket.\n");
      break;

    case WSAENETUNREACH:
      printf("The network can't be reached from this host at this time.\n");
      break;

    case WSAENOTSOCK: printf("The descriptor is not a socket.\n"); break;

    case WSAETIMEDOUT:
      printf("Attempt timed out without establishing a connection.\n");
      break;

    case WSAESOCKTNOSUPPORT:
      printf("Socket type is not supported in this address family.\n");
      break;

    case WSAENETDOWN: printf("Network subsystem failure.\n"); break;

    case WSAHOST_NOT_FOUND:
      printf("Authoritative Answer Host not found.\n");
      break;

    case WSATRY_AGAIN:
      printf("Non-Authoritative Host not found or SERVERFAIL.\n");
      break;

    case WSANO_RECOVERY:
      printf("Non recoverable errors, FORMERR, REFUSED, NOTIMP.\n");
      break;

    case WSANO_DATA:
      printf("Valid name, no data record of requested type.\n");
      break;

    case WSAEINPROGRESS:
      printf("address blocking Windows Sockets operation is in progress.\n");
      break;

    case WSAEINTR:
      printf("The (blocking) call was canceled via WSACancelBlockingCall().\n");
      break;

    default: printf("Unknown error %i.\n", WSAGetLastError()); break;
  }

  WSACleanup();
  exit(0);
}

#endif  //windows
