#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

struct route_table_entry *get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len)
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
				// print_ip_address(rtable[i].prefix);
				// print_ip_address(rtable[i].mask);
				// printf("#### %d\n", rtable[i].interface);
				best = &rtable[i];
			}
		}
	}

	return best;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Read route table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory rtable");
	int rtable_len = read_rtable(argv[1], rtable);

	// Read static arp table
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * 6);
	DIE(arp_table == NULL, "memory arp_table");
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + sizeof(struct ether_header));

		if (eth_hdr->ether_type != 0x0800)
		{
			continue;
		}

		// Look if checksum is good
		uint16_t old_check = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		if (old_check != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
		{
			printf("Packet cu CKECK gresit %x %x!\n", old_check, checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			// memset(buf, 0, sizeof(buf));
			continue;
		}

		// Discard packet if TTL is smaller than 2
		if (ip_hdr->ttl <= 1)
		{
			printf("The TTL has expired!\n");
			continue;
		}
		// uint8_t old_ttl;
		// old_ttl = ip_hdr->ttl;
		ip_hdr->ttl--;

		// Find next hop, if it exists

		struct route_table_entry *next_hop = get_best_route(ip_hdr->daddr, rtable, rtable_len);
		// The packet needs to be discarded
		if (next_hop == NULL)
		{
			memset(buf, 0, len);
			continue;
		}

		// Update the checksum
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		// Rewrite mac fields

		// Find the mac address of the router's interface for the source
		get_interface_mac(next_hop->interface, eth_hdr->ether_shost);

		// Find the mac address of the next hop for the destination
		for (int i = 0; i < arp_table_len; i++)
		{
			if (arp_table[i].ip == next_hop->next_hop)
			{
				memcpy(eth_hdr->ether_dhost, arp_table[i].mac, sizeof(eth_hdr->ether_dhost));
			}
		}
		// Send the ip packet to the next host
		send_to_link(next_hop->interface, buf, len);

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}
