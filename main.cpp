#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#define ETHER_SIZE 14
#define IP_SIZE 20
#define TCP_SIZE 20


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_info(struct libnet_ethernet_hdr* ether,struct libnet_ipv4_hdr* ip ,struct libnet_tcp_hdr* tcp, u_char* data){
	
	printf("src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",ether->ether_shost[5],ether->ether_shost[4],ether->ether_shost[3],ether->ether_shost[2],ether->ether_shost[1],ether->ether_shost[0]);
        
	printf("dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",ether->ether_dhost[5],ether->ether_dhost[4],ether->ether_dhost[3],ether->ether_dhost[2],ether->ether_dhost[1],ether->ether_dhost[0]);

        printf("src IP : %s\n",inet_ntoa(ip->ip_src));
        printf("dst IP : %s\n",inet_ntoa(ip->ip_dst));

        printf("src Port : %d\n" , ntohs(tcp->th_sport));
        printf("dst Port : %d\n", ntohs(tcp->th_dport));

        printf("DATA : ");
	if ((tcp->th_off*4)-TCP_SIZE==0) printf("data size is 0");

	else if((tcp->th_off*4)-TCP_SIZE<=16){
		for(int i=0; i< (tcp->th_off*4)-TCP_SIZE; i++)
        	{
                printf("%02x ",*(data + (tcp->th_off*4)-TCP_SIZE-i));
            	}
	}
	else {
                for(int i=0;i<16;i++)
                {
                        printf("%02x ",*(data+15-i));
                }
        }
        printf("\n\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
	struct libnet_ethernet_hdr* ether;
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	u_char* data;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

	ether = (struct libnet_ethernet_hdr*)packet;
        ip = (struct libnet_ipv4_hdr*) (packet+ETHER_SIZE);
        tcp = (struct libnet_tcp_hdr*) (packet + ETHER_SIZE+IP_SIZE);
        data = (u_char*) (packet + ETHER_SIZE+IP_SIZE+TCP_SIZE);
	if(ntohs(ether->ether_type)!= 0x0800) continue;
	if(ip->ip_p != 6)continue;
	print_info(ether,ip,tcp,data);

    }    

    pcap_close(handle);
}
