/*
 * Those structures are from net/ethernet.h and netinet/if_ether.g
 * For compatibility purpose, I decided to add this header together
 * with the code.
 *
 */

#ifndef __STRUCTURES_H
#define __STRUCTURES_H 1

/* This macro is used in the sniffing filter */
#define PCAP_NETMASK_UNKNOWN    0xffffffff


struct etherhdr {
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];	/* destination eth addr	*/
	u_int8_t  ether_shost[ETHER_ADDR_LEN];	/* source ether addr	*/
	u_int16_t ether_type;			/* packet type ID field	*/
};

struct arphdr {
	unsigned short int ar_hrd;		/* Format of hardware address.  */
	unsigned short int ar_pro;		/* Format of protocol address.  */
	unsigned char ar_hln;			/* Length of hardware address.  */
	unsigned char ar_pln;			/* Length of protocol address.  */
	unsigned short int ar_op;		/* ARP opcode (command).  */
};

struct ether_arp {
	struct	arphdr ea_hdr;			/* fixed-size header */
	u_int8_t arp_sha[ETHER_ADDR_LEN];	/* sender hardware address */
	u_int8_t arp_spa[4];			/* sender protocol address */
	u_int8_t arp_tha[ETHER_ADDR_LEN];	/* target hardware address */
	u_int8_t arp_tpa[4];			/* target protocol address */
};

#endif	/* structures.h */
