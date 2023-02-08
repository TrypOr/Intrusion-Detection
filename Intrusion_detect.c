#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6


/* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)

    /* TCP header */
    struct sniff_tcp {
        u_short th_sport;   /* source port */
        u_short th_dport;   /* destination port */
};

int main(int argc, char *argv[])
{

    int i;

     //error buffer
     char errbuff[PCAP_ERRBUF_SIZE];

     //open file and create pcap handler
     pcap_t * handler;

     //The header that pcap gives us
    struct pcap_pkthdr *header;
    //Read from alerts.txt

    //The actual packet 
    const u_char *packet;   
      int packetCount = 0;
 /* Open a capture file */
    if ((handler = pcap_open_offline("example_org_http.pcapng", errbuff) ) == NULL)
    {
        fprintf(stderr,"\nError opening dump file\n");
        return -1;
    }

      //write to file 
      FILE *fp = fopen ( "result.txt", "w" ) ;

      //tcp info
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    u_int size_ip;
    u_int size_tcp;

    while (pcap_next_ex(handler, &header, &packet) >= 0)
    {
        // Show the packet number
        printf("Packet # %i\n", ++packetCount);

        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n", header->len);

        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %d bytes\n", header->len);


        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n Program exiting\n", size_ip);
            break;
        }
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        printf("src address: %s src port: %d \n",  inet_ntoa(ip->ip_src), tcp->th_sport ); 
        printf("dest address: %s dest port: %d \n",inet_ntoa(ip->ip_dst) , tcp->th_dport);
        
         fprintf(fp," %s %d ",inet_ntoa(ip->ip_src),tcp->th_sport);
         fprintf(fp," %s  %d \n",inet_ntoa(ip->ip_dst) ,tcp->th_dport);
        // Add two lines between packets
        printf("\n");

    }
    fclose(fp);
    char flags[20][50];
    char src[30],dest[30];
    int srcp,destp;
    fp = fopen ( "result.txt", "r" ) ;
    int j;
    FILE* fptr;
    fptr=fopen("alerts.txt","r");
    for(j=0;j<20;j++){
        fscanf(fptr,"%s",&flags[j][0]);
    }
    while(fscanf(fp,"%s%d%s%d",&src[0],&srcp,&dest[0],&destp)!=EOF){
       for(j=0;j<20;j=j+5){       
            if(strcmp(flags[j],src)==0 && atoi(flags[j+1])==srcp  && atoi(flags[j+3])==destp && strcmp(flags[j+2],dest)==0){
                printf("\n Problem %s\n",flags[j+4]);          
            }
        }
    }
     return 0;
}