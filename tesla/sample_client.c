#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/ssl.h>

#include "client.h"
#include "sample.h"
#include <stdlib.h>
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif
#include <stdlib.h>
#include <string.h>

#define TERROR(rc)                                                             \
  if (rc != TESLA_OK) {                                                        \
    printf("Client failed %s:%i\n", __FILE__, __LINE__);                       \
    goto error;                                                                \
  }

int main(int argc, char **argv) {
  tesla_client_session client;
  TESLA_ERR rc = TESLA_OK;
  EVP_PKEY *pubkey = NULL;
  FILE *pfile;
  int64 rnonce;
  char *data = NULL;
  struct sockaddr_in sa;
  struct hostent *hp;
  struct sockaddr_in inetaddr;
  int outport;
  socklen_t inetaddrlen;
  int Datasocket;
  int Servsocket;
#ifdef WIN32
  //initialize the windows socket libraries
  WORD wVersionRequested = MAKEWORD(1, 1);
  WSADATA wsaData;
  if (WSAStartup(wVersionRequested, &wsaData) != 0) {
    printf("Error initializing\n");
    handle_error();
  }
#endif

  if (argc > 1) pfile = fopen(argv[1], "r");
  else
    pfile = fopen("pubkey.pem", "r");

  if (!pfile) {
    // no such file
    perror("fopen failed");
    exit(EXIT_FAILURE);
  }

  //very important
  ERR_load_crypto_strings();

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  //Allocate the client session
  //needs to be done FIRST
  if (pfile == NULL) {
    printf("Couldn't open public key");
    exit(-1);
  }
  pubkey = PEM_read_PUBKEY(pfile, NULL, NULL, NULL);
  fclose(pfile);

  client_alloc(&client);
  client_set_pkey(&client, pubkey);

  //generate a random nonce
  *(((int32 *) &rnonce) + 1) = (int32) time(NULL);
  rnonce += clock();
  //just to make this hard predict, xor with something weird from memory
  data = malloc(sizeof(int64));
  rnonce = rnonce ^ *(int64 *) data;
  free(data);
  //store it in the client session
  client_set_nonce(&(client), rnonce);

  //set a public key for the client
  //pubkey=PEM_read_PUBKEY(pfile,NULL,NULL,NULL);
  //client_set_pkey(&client,pubkey);

  /**** Establish a connection *****/
  printf("Client: Connecting to server %s:%i\n", HOSTNAME, SERVERPORT);
  if ((hp = gethostbyname(HOSTNAME)) == NULL) {
    printf("Error getting hostname!");
    exit(-1);
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = hp->h_addrtype;
  memcpy((char *) &sa.sin_addr, hp->h_addr, hp->h_length);
  sa.sin_port = htons(SERVERPORT);

  // Create a data socket to receive the data
  // to be authenticated
  memset(&inetaddr, 0, sizeof(inetaddr));
  inetaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  inetaddr.sin_family = AF_INET;
  inetaddr.sin_port = htons(CLIENTPORT);

  CHECKNEGPE(Datasocket = socket(AF_INET, SOCK_DGRAM, 0));
  CHECKNEGPE(bind(
      Datasocket, (struct sockaddr *) &inetaddr, sizeof(struct sockaddr_in)));
  inetaddrlen = sizeof(struct sockaddr_in);
  CHECKNEGPE(
      getsockname(Datasocket, (struct sockaddr *) &inetaddr, &inetaddrlen));
  outport = ntohs(inetaddr.sin_port);
  //good, we've got a connection to receive data on

  //Open a connection to the server
  CHECKNEGPE(Servsocket = socket(AF_INET, SOCK_STREAM, 0));
  CHECKNEGPE(connect(Servsocket, (struct sockaddr *) &sa, sizeof(sa)));
  /**** DONE, we now have an open connection ****/

  //really simple packet =  nlength | nonce
  {
    int32 s = htonl(client_nonce_len(&client));
    int psize = 4 + client_nonce_len(&client);
    data = malloc(psize);
    memcpy(data, &s, 4);
    rc = client_write_nonce(&client, data + 4, client_nonce_len(&client));
    printf("Client: Sending nonce\n");
    CHECKNEGPE(send(Servsocket, data, psize, 0));
    free(data);
    //the nonce was written
  }
  //receive the signature
  {
    int32 s;
    int len = recv(Servsocket, (char *) &s, 4, MSG_WAITALL);
    if (len != 4) {
      printf("Bad read\n");
      goto error;
    }
    s = ntohl(s);
    if (s > 1024) {
      printf("Message garbled\n");
      goto error;
    }
    data = malloc(s);
    len = recv(Servsocket, data, s, MSG_WAITALL);
    if (len != s) {
      printf("Bad read\n");
      goto error;
    }
    //read the incoming signature
    //printbuf(data,s);
    rc = client_read_sig_tag(&client, data, s);
    TERROR(rc);
    printf("Client: Bootstrapped signature tag successfully\n");
  }

#ifdef WIN32
  CHECKNEGPE(closesocket(Servsocket));
#else
  CHECKNEGPE(shutdown(Servsocket, 2));
#endif
  printf("Client: Receiving 200 messages\n");
  {
    int i = 0;
    int psize;
    tesla_auth_tag mtag;
    int dlen = client_auth_tag_size(&client);
    data = malloc(4 + dlen);
    rc = client_auth_tag_alloc(&client, &mtag);
    TERROR(rc);
    for (i = 0; i < 200; i++) {
      CHECKNEGPE(psize = recvfrom(Datasocket, data, 4 + dlen, 0, NULL, 0));
      if (psize != 4 + dlen) {
        printf("Client: Malformed packet\n");
        continue;
      }
      //read the authentication tag
      rc = client_read_auth_tag(&mtag, &client, data + 4, dlen);
      switch (rc) {
        case TESLA_OK: break;
        case TESLA_ERR_TIME_EXPIRED:
          /*According to the client, the key in the message could not
            have been sent by the server according to the maximum
            amount of time given to packet transmission */
          printf("CLIENT: The message violated the security condition");
          continue;
        case TESLA_ERR_KEY_INVALID:
          /*Indicates that the key in the tag did not match the stored
            key, the message has probably been tampered with */
          printf("CLIENT: The key in the message was invalid");
          continue;
        default: goto error;
      }
      rc = client_buffer(&client, &mtag, data, 4);
      TERROR(rc);
      rc = client_authenticate(&client, &mtag);
      {
        int mlen = 0;
        char *msg;
        int nmesgs = 0;
        /* Get the good messages */
        while ((msg = client_get_msg(&client, &mlen)) != NULL) {
          printf("Client: The message said :%u\n", ntohl(*(int32 *) msg));
          //tesla hands back dynamically allocated data
          free(msg);
          nmesgs++;
        }
        nmesgs = 0;
        /* Get the bad messages */
        while ((msg = client_get_bad_msg(&client, &mlen)) != NULL) {
          printf("Client: Bad message said :%u\n", ntohl(*(int32 *) msg));
          //tesla hands back dynamically allocated data
          free(msg);
          nmesgs++;
        }
      }
    }
  }
  printf("Client: DONE!\n");
  return 1;
error:
  printf("Client failed!\n");
  ctx_print_err(&(client.ctx));
  shutdown(Servsocket, 2);
  return -1;
}
