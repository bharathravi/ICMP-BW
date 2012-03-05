#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define BUFFSIZE 400
#define MTU 400

void Die(char *mess) { perror(mess); exit(1); }


void setIPHeader(struct ip *ip, in_addr_t from, in_addr_t to, size_t data_size) {
  ip->ip_dst.s_addr = to;
  ip->ip_src.s_addr = from;
  ip->ip_v = 4;
  ip->ip_hl = sizeof*ip >> 2;
  ip->ip_tos = 0;
  ip->ip_len = htons(data_size);
  ip->ip_id = htons(4321);
  ip->ip_off = htons(0);
  ip->ip_ttl = 255;
  ip->ip_p = 1;
  ip->ip_sum = 0;

  return;
}

void setICMPHeader(struct icmphdr *icmp) {
  icmp->type = 8;
  icmp->code = 0;
  // Header checksum with data is all zeroes.
  icmp->checksum = htons(~(ICMP_ECHO << 8));

  return;
}
    
void printStats(struct timeval sendtime, struct timeval recvtime,
                int packet_size, int total_recd) {
  long time_usecs = (recvtime.tv_sec - sendtime.tv_sec)*1000000 + (recvtime.tv_usec - sendtime.tv_usec);
  double bandwidth = 8*(packet_size + total_recd) / (double) time_usecs;
  printf("Total transfer size: %d\n", packet_size + total_recd); 
  printf("Took %ld microsecs\n", time_usecs);
  printf("BW %f Mbps\n", bandwidth);

  return;
}

int main(int argc, char *argv[]) {

  int sock;
  struct sockaddr_in echoserver;
  char *buffer, *recv_buffer;
  unsigned int echolen;
  struct ip *ip;
  struct iphdr *ip_reply;
  struct icmphdr *icmp = (struct icmphdr *)(ip + 1);
  struct sockaddr_in dest;
  int addr_length;
  int on = 1, off = 0, offset;
  int total_recd = 0;
  int num_packets, packet_size;
  int size_remaining;
  in_addr_t from, to;
  struct timeval sendtime, recvtime;

  if (argc < 3) {
    printf("Usage:\n ping <source ip> <target ip> <packet size> <number of packets>\n");
    return;
  } else {
    from = inet_addr(argv[1]);
    to = inet_addr(argv[2]);
    packet_size = atoi(argv[3]);
    if (packet_size % MTU != 0) {
      printf("Packet size must be a multiple of %d\n", MTU);
    }
    num_packets = atoi(argv[4]);
  }

  buffer = (char *)malloc(sizeof(char) * MTU);
  recv_buffer = (char *)malloc(sizeof(char) * packet_size);
  ip = (struct ip *)buffer;
  icmp = (struct icmphdr *)(ip + 1);

  /* Create the TCP socket */
  if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    Die("Failed to create socket");
  }

  bzero(buffer, sizeof(buffer));

  // Define a custom IP header
  if(setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &off, sizeof(off)) < 0) {
    perror("setsockopt() for IP_MTU_DISCOVER error");
    exit(1);
  }

  // Set IP header
  setIPHeader(ip, from, to, sizeof(buffer));

  // Set ICMP header
  setICMPHeader(icmp);  

  // Set destination address
  dest.sin_addr = ip->ip_dst;   
  dest.sin_family = AF_INET;
  /* sending time */
  gettimeofday(&sendtime, NULL);

  // Break packet into fragments and send
  size_remaining = packet_size;
  offset = 0;
  do {
    printf("%d ", offset);
    ip->ip_off = htons(offset >> 3);

    if(size_remaining == MTU)
      ip->ip_off |= htons(0x2000);
    else
      ip->ip_len = htons(MTU); /* make total 65538 */

    if (size_remaining > MTU) {

    }
    if(sendto(sock, buffer, MTU, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
      fprintf(stderr, "offset %d: ", offset);
      perror("sendto() error");
    } else {
      printf("sendto() is OK.\n");
    }

    /* IF offset = 0, define our ICMP structure */
    if(offset == 0) {
      icmp->type = 0;
      icmp->code = 0;
      icmp->checksum = 0;
    }
    size_remaining -= MTU;
    offset += MTU - sizeof(struct ip);
  } while (size_remaining > 0);

  addr_length = sizeof(dest);
  if ( (total_recd = recvfrom(sock,recv_buffer, packet_size, 0 , (struct sockaddr *)&dest, &addr_length)) < 0) {
    perror("recvfrom() error");
  }  
  gettimeofday(&recvtime, NULL);

  ip_reply = (struct iphdr*) recv_buffer;
  printf("ID: %d\n", ntohs(ip_reply->id));
  printf("TTL: %d\n", ip_reply->ttl);


  // TODO(bharath): Parse the return packet more intelligently.
  if (total_recd == packet_size) {
    // All went well calculate time.
    printf("Recd %d\n", total_recd);
    printStats(sendtime, recvtime, packet_size, total_recd);
  } else {
    printf("Unexpected return packet\n");
    printf("Recd %d\n", total_recd);
  }
  
  return 0;
}

