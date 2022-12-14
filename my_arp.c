#include "my_arp.h"
#include <assert.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>


#define IFNAME "tap0"
#define BUFLEN 1600
#define CLEAR(x) memset(&(x), 0x00, sizeof(x))

static int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        perror("Cannot open TUN/TAP dev\n"
                    "Make sure one exists with "
                    "'$ mknod /dev/net/tun c 10 200'");
        exit(1);
    }

    CLEAR(ifr);

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if( *dev ) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        perror("ERR: Could not ioctl tun");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

__be16 print_eth_header_and_get_proto(uint8_t* buf)
{
  struct ethhdr *eth = (struct ethhdr *)(buf);
  printf("\nEthernet Header\n");
  printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
  printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
  printf("\t|-Protocol : %d\n",htons(eth->h_proto));

  return eth->h_proto;

}

void print_arp_info(uint8_t* buf)
{
        printf("#####################################################\n");
        printf("#####################################################\n");
        struct my_arphdr *arp = (struct my_arphdr*)(buf + 14);
        printf("\nARP Header\n");
        printf("\t|-Source MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arp->ar_sha[0],arp->ar_sha[1],arp->ar_sha[2],arp->ar_sha[3],arp->ar_sha[4],arp->ar_sha[5]);
        printf("\t|-Source IP : %d-%d-%d-%d\n",arp->ar_sip[0],arp->ar_sip[1],arp->ar_sip[2],arp->ar_sip[3]);
        printf("\t|-Target MAC : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arp->ar_tha[0],arp->ar_tha[1],arp->ar_tha[2],arp->ar_tha[3],arp->ar_tha[4],arp->ar_tha[5]);
        printf("\t|-Target IP : %d-%d-%d-%d\n",arp->ar_tip[0],arp->ar_tip[1],arp->ar_tip[2],arp->ar_tip[3]);
        printf("op id: %d\n", htons(arp->ar_op));
        printf("#####################################################\n");
        printf("#####################################################\n");

}

void craft_arp_reply(uint8_t* request_buf, uint8_t* reply_buf)
{
    struct my_arphdr *arp = (struct my_arphdr*)(request_buf + 14);
    struct my_arphdr *arp_reply = (struct my_arphdr*)(reply_buf+ 14);
    struct ethhdr *eth = (struct ethhdr *)(request_buf);

    // set proto to Reply (is-at)
    arp_reply->ar_op = ntohs(2);

    // set source MAC and IP to random Value;
    
    arp_reply->ar_sha[0] = 1;
    arp_reply->ar_sha[1] = 1;
    arp_reply->ar_sha[2] = 1;
    arp_reply->ar_sha[3] = 1;
    arp_reply->ar_sha[4] = 1;
    arp_reply->ar_sha[5] = 1;

    arp_reply->ar_sip[0] = arp->ar_tip[0];
    arp_reply->ar_sip[1] = arp->ar_tip[1];
    arp_reply->ar_sip[2] = arp->ar_tip[2];
    arp_reply->ar_sip[3] = arp->ar_tip[3];

    //set target ip to adn MAC to itself

    arp_reply->ar_tha[0] = arp->ar_sha[0];
    arp_reply->ar_tha[1] = arp->ar_sha[1];
    arp_reply->ar_tha[2] = arp->ar_sha[2];
    arp_reply->ar_tha[3] = arp->ar_sha[3];
    arp_reply->ar_tha[4] = arp->ar_sha[4];
    arp_reply->ar_tha[5] = arp->ar_sha[5];

    arp_reply->ar_tip[0] = arp->ar_sip[0];
    arp_reply->ar_tip[1] = arp->ar_sip[1];
    arp_reply->ar_tip[2] = arp->ar_sip[2];
    arp_reply->ar_tip[3] = arp->ar_sip[3];

    // set source and target of ethernet frame

    struct ethhdr *eth_reply = (struct ethhdr *)(reply_buf);
    eth_reply->h_source[0] = 1;
    eth_reply->h_source[1] = 1;
    eth_reply->h_source[2] = 1;
    eth_reply->h_source[3] = 1;
    eth_reply->h_source[4] = 1;
    eth_reply->h_source[5] = 1;

    eth_reply->h_dest[0] = eth->h_source[0];
    eth_reply->h_dest[1] = eth->h_source[1];
    eth_reply->h_dest[2] = eth->h_source[2];
    eth_reply->h_dest[3] = eth->h_source[3];
    eth_reply->h_dest[4] = eth->h_source[4];
    eth_reply->h_dest[5] = eth->h_source[5];

    //print_eth_header_and_get_proto(reply_buf);

} 

int main(int argc, char** argv) 
{
    char dev[IFNAMSIZ];
    int tun_fd;

    if (argc > 1) {
    assert(strlen(argv[1]) < IFNAMSIZ);
    strcpy(dev, argv[1]);
    } else {
    strcpy(dev, IFNAME);
    }

    printf("device name: %s\n", dev);

    tun_fd = tun_alloc(dev);

    int running = 1;
    uint8_t buf[BUFLEN];

    while (running) {
        int nread;

        if ((nread = read(tun_fd, buf, BUFLEN)) < 0) {
        perror("ERR: Read from tun_fd");
        break;
        }

        __be16 eth_proto = print_eth_header_and_get_proto(buf);
        if (htons(eth_proto) == 2054)
        {

        struct my_arphdr *arp = (struct my_arphdr*)(buf + 14);
        if (htons(arp->ar_op) == 2) continue;

        uint8_t arp_reply_buf[42];
        memcpy(arp_reply_buf, buf, 42*sizeof(uint8_t));

        //print_arp_request_info(buf);
        craft_arp_reply(buf, arp_reply_buf);
        print_arp_info(arp_reply_buf);


        int ret = write(tun_fd,arp_reply_buf, 42);

        if (ret == -1)
        {
            printf("didnt reply\n");
        }
    }


    printf("Read %d bytes from device %s\n", nread, dev);
  }

  close(tun_fd);

  return EXIT_SUCCESS;
}