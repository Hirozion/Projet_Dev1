#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN_STR 18
#define IP_ADDR_LEN_STR 16

#define ARP 2054
#define IPV4 2048
#define IPV6 34525
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6
#define ICMP_PROTOCOL 1

#define ERROR -1
/*------------------------------------------------------------------------------------------------------------------------------*/
/* Ethernet header */
struct sniff_ethernet 
{
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};
/*------------------------------------------------------------------------------------------------------------------------------*/
/* IP header */
struct sniff_ip
{
        u_char ip_vhl;          /* version << 4 | header length >> 2 */
        u_char ip_tos;          /* type of service */
        u_short ip_len;         /* total length */
        u_short ip_id;          /* identification */
        u_short ip_off;         /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char ip_ttl;          /* time to live */
        u_char ip_p;            /* protocol */
        u_short ip_sum;         /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};
/*------------------------------------------------------------------------------------------------------------------------------*/
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
/*------------------------------------------------------------------------------------------------------------------------------*/
/* TCP header */
typedef u_int tcp_seq;
/*------------------------------------------------------------------------------------------------------------------------------*/
struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};
/*------------------------------------------------------------------------------------------------------------------------------*/
struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};
/*------------------------------------------------------------------------------------------------------------------------------*/
struct custom_udp
{
        int source_port;
        int destination_port;
        unsigned char *data;

} typedef UDP_segment;
/*------------------------------------------------------------------------------------------------------------------------------*/
struct custom_tcp
{
        int source_port;
        int destination_port;
        int sequence_number;
        int ack_number;
        int th_flag;
        unsigned char *data;
        int data_length;

} typedef TCP_Segment;
/*------------------------------------------------------------------------------------------------------------------------------*/
struct custom_ip
{
        char source_ip[IP_ADDR_LEN_STR];
        char destination_ip[IP_ADDR_LEN_STR];
        int ip_protocol; //tcp -- udp -- icmp ip_protocol == rules_ds[i].protocol -- tcp == tcp
        TCP_Segment data;
        UDP_segment data_UDP;

} typedef IP_Packet;
/*------------------------------------------------------------------------------------------------------------------------------*/
struct custom_ethernet
{
        char source_mac[ETHER_ADDR_LEN_STR];
        char destination_mac[ETHER_ADDR_LEN_STR];
        int ethernet_type;
        int frame_size;
        IP_Packet data;

} typedef ETHER_Frame;
/*------------------------------------------------------------------------------------------------------------------------------*/
typedef struct ids_option
{
   char *key;
   char *values;     
} Option;
/*------------------------------------------------------------------------------------------------------------------------------*/
typedef struct ids_rule
{
        char type[10];
        char protocol[10];
        char source_IP[IP_ADDR_LEN_STR];
        char port_source[10];
        char direction[10];
        char destination_IP[IP_ADDR_LEN_STR];
        char port_destination[10];
        Option ids_option;
}Rule;
/*------------------------------------------------------------------------------------------------------------------------------*/
typedef enum
{
	false = 0,
	true = 1
}Bool;
/*------------------------------------------------------------------------------------------------------------------------------*/
int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet,ETHER_Frame * frame);
void print_payload(int payload_length, unsigned char *payload);
void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int count);
void read_rules(FILE * file, Rule *rules_ds, int count);
void free_memory(Rule *rules_ds, int count);
int count_lines_from_file(FILE *fic);
void generate_syslog(char *log_msg);
Bool search_web_content(char *values, char *date);
