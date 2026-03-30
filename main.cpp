#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "headers.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(uint8_t* mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip) {
	ip = ntohl(ip);
	printf("%u.%u.%u.%u", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		ethernet_header ethernet;
		ip_header ip;
		tcp_header tcp;

		memcpy(&ethernet, packet, sizeof(ethernet_header));

		if(ntohs(ethernet.ethertype) != 0x0800)
			continue;

		print_mac(ethernet.src_mac);
		printf(" -> ");
		print_mac(ethernet.dst_mac);
		printf(", ");

		memcpy(&ip, packet + 14, sizeof(ip_header));


		int ip_header_len = (ip.ver_ihl & 0x0F) * 4;

		memcpy(&tcp, packet + 14 + ip_header_len, sizeof(tcp_header));

		int tcp_header_len = ((tcp.offset_reserved >> 4) & 0x0F) * 4;

		print_ip(ip.src_ip);
		printf(":%u", ntohs(tcp.src_port));
		printf(" -> ");
		print_ip(ip.dst_ip);
		printf(":%u", ntohs(tcp.dst_port));

		if(ip.protocol != 6)
			continue;
		const u_char* payload = packet + 14 + ip_header_len + tcp_header_len;

		int payload_len = header->caplen - (14 + ip_header_len + tcp_header_len);

		if(payload_len < 0) payload_len = 0;

		int print_len = payload_len > 20 ? 20 : payload_len;

		printf("\n");
		if(print_len == 0){
			printf("-");
		}
		else{
			for(int i = 0; i < print_len; i++) {
				printf("%02x|", payload[i]);
			}
		}
		printf("\n");
		printf("======================================================================");
		printf("\n");
	}

	pcap_close(pcap);
}

