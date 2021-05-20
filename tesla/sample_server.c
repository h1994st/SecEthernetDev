#include "tesla.h"
#include "sender.h"
#include "sample.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#define T_INT 1000
#define D_INT 3
#define TERROR(rc) if(rc!=TESLA_OK) goto error
#define ERR(msg) {printf(msg); goto error;}

int main(void){
  //sender object
  tesla_sender_session server;
  //T_int, how long we want the intervals to be
  NTP_t T_int;
  TESLA_ERR rc;
  struct sockaddr_in inetaddr;
  struct sockaddr_in peer;
  int addrlen = sizeof(peer);
  int sockfd;
  int peerfd;
#define HOSTNAME_LEN 256
  char hostname[HOSTNAME_LEN];
  char replybuffer[1024];
  char * data=NULL;
  FILE * pfile;
  EVP_PKEY *pkey;
  int32 dlen=0;
  int32 nlen=0;
  int32 client_ip;
#define BUFBIG(x) if(x>1024){printf("Too long!\n");exit(-1);}
  /*Set up the sockets if needed */
#ifdef WIN32
  WORD wVersionRequested = MAKEWORD(1,1);
  WSADATA wsaData;  
  if ( WSAStartup( wVersionRequested, &wsaData ) != 0 )
    handle_error();
#endif

  /** Set up openssl */
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  
  X509V3_add_standard_extensions();
  SSLeay_add_all_algorithms();
  //read the private key
  pfile=fopen("privkey.pem","r");
  if(pfile==NULL) ERR("Couldn't open private key");
  pkey=PEM_read_PrivateKey(pfile,NULL,NULL,NULL);
  if(pkey==NULL) ERR("Couldn't read private key");
  fclose(pfile);
  

  /*Sender set up, allocate the session structure and start the sender session */
  T_int=NTP_fromMillis(T_INT);
  //sender init uses the default key length, but it still needs a random key
  data=malloc(DEFAULT_KEYL);
  //more robust implementations should use something more random
  rc=sender_init(&server,&T_int,D_INT,2500,data);
  free(data);
  TERROR(rc);
  //set the sender's private key
  sender_set_pkey(&server,pkey);
  //starts the tesla sender session
  sender_start(&server);

  /* Open the socket where we accept incoming connections */
  memset((void *) &inetaddr, 0, sizeof(inetaddr));
  inetaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  inetaddr.sin_family = AF_INET;
  inetaddr.sin_port = htons( SERVERPORT );
  
  CHECKNEGPE( sockfd = socket(AF_INET, SOCK_STREAM,0));
  CHECKNEGPE( bind(sockfd, (struct sockaddr *) &inetaddr, sizeof(struct sockaddr_in)));
  CHECKNEGPE( listen(sockfd, 5));
  
  CHECKNEGPE( gethostname( hostname, HOSTNAME_LEN ));
  printf( "Server started on host %s on port %u\n", hostname, SERVERPORT );
  while (( peerfd = accept( sockfd, (struct sockaddr *) &peer, &addrlen )) < 0 ) {
    perror( "Accept error, exiting\n" );
    exit( 1 );
  }
  client_ip=ntohl(peer.sin_addr.s_addr);
  printf( "Server: Connection from %u.%u.%u.%u:%u\n",
	  IP_ADDR_FORMAT( client_ip),
	  (unsigned) ntohs( peer.sin_port ));

  //sleep(1);//simulate a little bit of network delay
  //receive the nonce
  {
    CHECKNEGPE( recv(peerfd,(char *)&nlen, 4,MSG_WAITALL));//read the nlength
    nlen = ntohl(nlen);
    BUFBIG(nlen);
    printf("Server: Receiving nonce %i\n",nlen);
    CHECKNEGPE( recv(peerfd, replybuffer, nlen,MSG_WAITALL));
    //we've got the nonce
    printf("Server: Nonce received\n");
  }
  //sig tag size is constant once the session has been allocated
  dlen=4+sender_sig_tag_size(&server);
  data=malloc(dlen);
  //send the signature tag
  {
    int32 s=sender_sig_tag_size(&server);
    printf("Server: Sending signature tag\n");
    s=htonl(s);
    memcpy(data,&s,4);
    //write the signature to the buffer
    //read the nonce from the replybuffer
    rc=sender_write_sig_tag(&server,data+4,dlen-4,replybuffer,nlen);
    TERROR(rc);
    //write the signature tag to the client
    CHECKNEGPE( send(peerfd,data,dlen,0));
  }
  free(data);
  //we're going to assume success from the client
#ifdef WIN32
  CHECKNEGPE(closesocket(peerfd));
#else
  CHECKNEGPE( shutdown(peerfd,2));
#endif

  printf("Server: Entering send loop\n");
  {
    struct sockaddr_in inetaddr;
    struct sockaddr_in receiver;
    int sockfd,i;
    int *RAND=malloc(4*200);
    /*Set up a socket to send UDP data to the client */
    memset((char *) &inetaddr, 0, sizeof(inetaddr));
    inetaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    inetaddr.sin_family = AF_INET;
    inetaddr.sin_port = htons( SERVERUDPOUT );
    
    CHECKNEGPE( sockfd = socket(AF_INET, SOCK_DGRAM, 0));
    CHECKNEGPE( bind(sockfd, (struct sockaddr *) &inetaddr, sizeof(struct sockaddr_in)));
    //the outgoing udp port is set up
    //set up the address of this client
    memset((char *) &receiver, 0, sizeof(inetaddr));
    receiver.sin_family = AF_INET;
    receiver.sin_addr.s_addr = htonl( client_ip);
    receiver.sin_port = htons( CLIENTPORT );
    //the packet routing info is set up
    //allocate the packet information
    dlen=sender_auth_tag_size(&server);
    data=malloc(4+dlen);

    for(i=0;i<200;i++){
      int s=htonl(i);
      memcpy(data,&s,4);
      rc=sender_write_auth_tag(&server,&s,4,data+4,dlen);
      TERROR(rc);
      printf("Server: Sending %i\n",i);
      if(i % 3!=0)
      CHECKNEGPE( sendto( sockfd, data, dlen+4, 0,
			  &receiver, sizeof(receiver)));
      
      if(i % 2!=0){
	memcpy(data,&RAND[i],4);
	CHECKNEGPE( sendto( sockfd, data, dlen+4, 0,
			  &receiver, sizeof(receiver)));
      }
      sleep(1);
    }
  }
  return 0;
 error:
  ctx_print_err(&(server.ctx));
  return -1;
}
