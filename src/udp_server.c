// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define PORT    8080
#define MAXLINE 32

int sockfd = -1;
uint8_t buffer[MAXLINE];

void signal_handler(int signum) {
  // close socket
  if (sockfd != -1) close(sockfd);

  exit(signum);
}

int main() {
  struct sockaddr_in servaddr, cliaddr;

  // register handler
  signal(SIGINT, signal_handler);
  signal(SIGKILL, signal_handler);
  signal(SIGTERM, signal_handler);

  // Creating socket file descriptor
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));

  // Filling server information
  servaddr.sin_family = AF_INET; // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(PORT);

  // Bind the socket with the server address
  if (bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
    perror("bind failed");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  ssize_t n;

  socklen_t len = sizeof(cliaddr); // len is value/resuslt

  while (true) {
    n = recvfrom(
        sockfd, (char *) buffer, MAXLINE, MSG_WAITALL,
        (struct sockaddr *) &cliaddr, &len);

    printf("Client: %ld bytes\n", n);
    for (int i = 0; i < n; ++i) {
      printf("%02X ", buffer[i]);
    }
    printf("\n\n");
  }

  close(sockfd);
  return 0;
}
