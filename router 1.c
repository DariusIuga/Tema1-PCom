#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct mac_entry *mac_table;
int mac_table_len;

void print_ip_address(uint32_t ip_addr)
{
	uint8_t *ip_bytes = (uint8_t *)&ip_addr;
	printf("%d.%d.%d.%d\n", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
}
/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++)*/
	struct route_table_entry *best = NULL;
	for (int i = 0; i < rtable_len; i++)
	{
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix)
		{

			if (best == NULL)
				best = &rtable[i];
			else if (ntohl(best->mask) < ntohl(rtable[i].mask))
			{

				print_ip_address(rtable[i].prefix);
				print_ip_address(rtable[i].mask);
				printf("#### %d\n", rtable[i].interface);
				best = &rtable[i];
			}
		}
	}

	return best;
}

struct mac_entry *get_mac_entry(uint32_t ip_dest)
{
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches ip_dest. */

	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */

	for (int i = 0; i < mac_table_len; i++)
	{
		if (mac_table[i].ip == ip_dest)
		{
			return &mac_table[i];
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int interface;
	char buf[MAX_LEN];
	int len;

	/* Don't touch this */
	init();

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(struct mac_entry) * 100);
	DIE(mac_table == NULL, "memory");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable("rtable.txt", rtable);
	mac_table_len = read_mac_table(mac_table);

	while (1)
	{
		/* We call get_packet to receive a packet. get_packet returns
		the interface it has received the data from. And writes to
		len the size of the packet. */
		interface = recv_from_all_links(buf, &len);
		DIE(interface < 0, "get_message");
		printf("We have received a packet %d %d\n", MAX_LEN, len);

		/* Extract the Ethernet header from the packet. Since protocols are
		 * stacked, the first header is the ethernet header, the next header is
		 * at m.payload + sizeof(struct ether_header) */
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum(ip_hdr, sizeof(struct iphdr)) */
		uint16_t old_check = ip_hdr->check;
		ip_hdr->check = 0;
		if (old_check != htons(ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))))
		{
			printf("Packet cu CKECK gresit %x %x!\n", old_check, htons(ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))));
			memset(buf, 0, sizeof(buf));
			continue;
		}

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *best_router = get_best_route(ip_hdr->daddr);
		if (best_router == NULL)
		{
			printf("NU exista cale in tabela de rutare !\n");
			continue;
		}

		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum using the incremental forumla  */
		if (ip_hdr->ttl <= 1)
		{
			printf("TTL expirat !\n");
			continue;
		}
		uint8_t old_ttl;
		old_ttl = ip_hdr->ttl;
		ip_hdr->ttl--;

		ip_hdr->check = ~(~old_check + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		struct mac_entry *nexthop_mac = get_mac_entry(best_router->next_hop);
		if (nexthop_mac == NULL)
		{
			printf("NU s-a gasit MAC-ul destinatiei !\n");
			continue;
		}

		memcpy(eth_hdr->ether_dhost, nexthop_mac->mac, sizeof(eth_hdr->ether_dhost));
		get_interface_mac(best_router->interface, eth_hdr->ether_shost);

		// Call send_to_link(best_router->interface, packet, len);
		printf("Packet transmis pe %d!\n", best_router->interface);
		send_to_link(best_router->interface, buf, len);
	}
}
