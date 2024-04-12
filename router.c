

#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib.h"
#include "protocols.h"
#include "queue.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *mac_table;
int mac_table_len;

// Cazul Echo reply
void echo_reply(char *buf, int interface, struct ether_header *eth_hdr,
                struct iphdr *ip_hdr, size_t len)
{
    // reinitializarea interfetei
    get_interface_mac(interface, eth_hdr->ether_shost);
    // inversarea sursei si a destinatiei
    uint8_t aux[6];
    memcpy(aux, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
    memcpy(eth_hdr->ether_shost, aux, sizeof(eth_hdr->ether_shost));

    // completarea header-ului ip
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = checksum((uint16_t *)(ip_hdr), sizeof(struct iphdr));

    // completarea header-ului icmp
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf +
                                                  sizeof(struct ether_header) + sizeof(struct iphdr));
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
    // recalcularea checksum-ului
    icmp_hdr->checksum = checksum((uint16_t *)(icmp_hdr), sizeof(struct icmphdr));
    // trimiterea pachetului
    send_to_link(interface, buf, len);
}

// Cazul Time exceeded and case Destination unreachable
void icmp_err(uint8_t type, char *buf, int interface, struct ether_header *eth_hdr,
              struct iphdr *ip_hdr, size_t len)
{
    // reinitializarea interfetei
    get_interface_mac(interface, eth_hdr->ether_shost);

    // completarea header-ului ip
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = checksum((uint16_t *)(ip_hdr), sizeof(struct iphdr));
    ip_hdr->ttl = 255; // reinitializarea ttl-ului

    // completarea header-ului icmp
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
    icmp_hdr->type = type; // 11 pentru cazul Time exceeded sau 3 in cazul Destination unreachable
    icmp_hdr->checksum = checksum((uint16_t *)(icmp_hdr), sizeof(struct icmphdr));
    memcpy(icmp_hdr + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));

    // reactualizare len
    len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

    // noul buffer va contine, deasupra headerului ICMP, headerul de IPv4 al pachetului dropped,
    // precum și primii 64 de biți din payload-ul pachetului original
    char *new_buf = (char *)malloc(len);
    memcpy(new_buf, eth_hdr, sizeof(struct ether_header));
    size_t offset = sizeof(struct ether_header);
    memcpy(new_buf + offset, ip_hdr, sizeof(struct iphdr));
    offset += sizeof(struct iphdr);
    memcpy(new_buf + offset, icmp_hdr, sizeof(struct icmphdr));
    offset += sizeof(struct icmphdr);
    memcpy(new_buf + offset, buf + sizeof(struct ether_header), sizeof(struct iphdr) + 64);
    // trimiterea pachetului
    send_to_link(interface, new_buf, len);
}

// Functia de compare folosita in qsort pentru sortarea descrescatoare a intrarilor
// in tabela dupa prefix si masca
int cmp(const void *p1, const void *p2)
{
    const struct route_table_entry *a_route = (const struct route_table_entry *)p1;
    const struct route_table_entry *b_route = (const struct route_table_entry *)p2;

    // ordonare dupa masca
    if ((b_route->prefix & b_route->mask) == (a_route->prefix & a_route->mask))
    {
        return ntohl(b_route->mask) > ntohl(a_route->mask);
    }
    else
    { // ordonare dupa prefix
        return ntohl(b_route->prefix & b_route->mask) >
               ntohl(a_route->prefix & a_route->mask);
    }
}

// Functia utilizeaza o cautare binara pentru a gasi in tabela de rutare ruta cea mai specifica
// pentru adresa IP primita ca parametru
struct route_table_entry *get_best_route(uint32_t dest_ip)
{
    int left = 0, right = rtable_len - 1, mid, pos = -1;
    uint32_t max_mask = 0;

    // cat timp se mai poate cauta
    while (left <= right)
    {
        mid = (left + right) / 2;
        if ((dest_ip & rtable[mid].mask) == (rtable[mid].prefix & rtable[mid].mask))
        {
            // daca s-a gasit o ruta satisfacatoare, se retine atat pozitia sa in tabela
            // de rutare, cat si masca acesteia
            if (ntohl(rtable[mid].mask) > max_mask)
            {
                max_mask = ntohl(rtable[mid].mask);
                pos = mid;
            }
            right = mid - 1; // se cauta in stanga
        }
        else if (ntohl(dest_ip & rtable[mid].mask) >
                 ntohl(rtable[mid].prefix & rtable[mid].mask))
        {
            right = mid - 1; // se cauta in stanga
        }
        else
        {
            left = mid + 1; // se cauta in dreapta
        }
    }
    // daca s-a gasit o ruta, se intoarce pointer catre aceasta, sau NULL in caz contrar
    return (pos >= 0) ? &rtable[pos] : NULL;
}

// Functia returneaza intrarea corespunzatoare adresei IP a urmatorului hop din tabela ARP
struct arp_table_entry *get_arp_entry(uint32_t ip)
{
    for (int i = 0; i < mac_table_len; i++)
    {
        if ((mac_table + i)->ip == ip)
            return (mac_table + i);
    }
    // daca nu s-a gasit intrarea corespunzatoare, se intoarce NULL
    return NULL;
}

// Functia folosita in cazul router_arp_reply, care proceseaza elementele din coada de
// asteptare si apoi le trimite pe interfata corespunzatoare
void reply_arp(struct arp_header *arp_hdr, struct queue *q)
{
    // adaugarea in tabela mac a expeditorului ARP
    mac_table[mac_table_len].ip = arp_hdr->spa;
    memcpy(mac_table[mac_table_len].mac, arp_hdr->sha, ETH_ARP_LEN);
    mac_table_len++; // reactualizarea dimensiunii tabelei

    // parcurgerea cozii de buffere
    while (queue_empty(q) == 0)
    {
        // retinerea primului element din coada
        char *new_buf = queue_deq(q);
        struct ether_header *new_eth = (struct ether_header *)new_buf;
        struct iphdr *new_ip = (struct iphdr *)(new_buf + sizeof(struct ether_header));

        struct route_table_entry *next_router = get_best_route(new_ip->daddr);

        // daca exista o ruta specifica
        if (next_router != NULL)
        {
            get_interface_mac(next_router->interface, new_eth->ether_shost);
            memcpy(new_eth->ether_dhost, arp_hdr->sha, ETH_ARP_LEN);
            new_eth->ether_type = ntohs(ETHERTYPE_IP);

            // reactualizarea lungimii
            size_t len = sizeof(struct ether_header) + ntohs(new_ip->tot_len);
            send_to_link(next_router->interface, new_buf, len);
        }
        else
        { // daca nu exista o ruta specifica, se trece la urmatorul pachet
            continue;
        }
    }
}

// Functie necesara pentru cazul in care nu exista un nex_hop in tabela ARP
void no_next_hop(char *buf, struct route_table_entry *best_router)
{
    // completare noii structuri ether_header
    struct ether_header *new_eth = malloc(sizeof(struct ether_header));
    get_interface_mac(best_router->interface, new_eth->ether_shost);
    memset(new_eth->ether_dhost, 0xff, ETH_ARP_LEN);
    new_eth->ether_type = htons(ETHERTYPE_ARP);

    // completarea noii structuri arp_header
    struct arp_header *new_arp = malloc(sizeof(struct arp_header));
    memset(new_arp->tha, 0xff, ETH_ARP_LEN);
    new_arp->htype = htons(ARPOP_REQUEST);
    new_arp->ptype = htons(ETHERTYPE_IP);
    new_arp->hlen = 6;
    new_arp->plen = 4;
    new_arp->op = htons(ARPOP_REQUEST);

    new_arp->tpa = best_router->next_hop;
    get_interface_mac(best_router->interface, new_arp->sha);
    new_arp->spa = inet_addr(get_interface_ip(best_router->interface));

    // completarea buffer-ului
    memcpy(buf, new_eth, sizeof(struct ether_header));
    memcpy(buf + sizeof(struct ether_header), new_arp, sizeof(struct arp_header));
    // redefinirea lungimii
    size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

    send_to_link(best_router->interface, buf, len);
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    /* Code to allocate the MAC and route tables */
    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    DIE(rtable == NULL, "memory");
    rtable_len = read_rtable(argv[1], rtable);

    // ordonarea tabelei de rutare dupa prefix si masca
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmp);

    mac_table = malloc(sizeof(struct route_table_entry) * 100000);
    DIE(mac_table == NULL, "memory");
    mac_table_len = 0;

    struct queue *q = queue_create();
    DIE(q == NULL, "error");

    while (1)
    {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *)buf;
        struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

        switch (eth_hdr->ether_type)
        {
        // This is an IP packet
        case 0x0008:
            uint16_t old_check = ip_hdr->check;
            ip_hdr->check = 0;
            if (old_check != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))))
            {
                memset(buf, 0, sizeof(buf));
                continue;
            }
            // gasirea rutei specifice pentru adresa IP data
            struct route_table_entry *best_router = get_best_route(ip_hdr->daddr);

            if (best_router == NULL)
            {
                // cazul Destination unreachable
                icmp_err(ICMP_DESTINATION_UNREACHABLE, buf, interface, eth_hdr, ip_hdr, len);
                continue;
            }
            else
            {
                if (ip_hdr->ttl <= 1)
                {
                    // cazul Time exceeded
                    icmp_err(ICMP_TIME_EXCEEDED, buf, interface, eth_hdr, ip_hdr, len);
                    continue;
                }
                else
                {
                    // cazul Echo reply
                    if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr)
                    {
                        echo_reply(buf, interface, eth_hdr, ip_hdr, len);
                        continue;
                    }
                    else
                    {
                        uint16_t old_ttl = ip_hdr->ttl;
                        ip_hdr->ttl--; // decremenatrea TTL-ului
                        // refacerea checksum-ului
                        ip_hdr->check = ~(~old_check + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

                        struct arp_table_entry *nexthop_mac = get_arp_entry(best_router->next_hop);
                        // cazul in care nu exista urmatorul hop in tabela ARP
                        if (nexthop_mac == NULL)
                        {
                            // copierea in coada a vechiului buf
                            char *new_buf = malloc(sizeof(buf));
                            memcpy(new_buf, buf, sizeof(buf));
                            queue_enq(q, new_buf);
                            // folosirea functiei specifice
                            no_next_hop(buf, best_router);
                            continue;
                        }
                        else
                        { // transmiterea pachetului
                            memcpy(eth_hdr->ether_dhost, nexthop_mac->mac,
                                   sizeof(eth_hdr->ether_dhost));
                            get_interface_mac(best_router->interface, eth_hdr->ether_shost);
                            send_to_link(best_router->interface, buf, len);
                        }
                    }
                }
            }
            break;

        // This is an ARP packet
        case 0x0608:
            // crearea structurii de tip struct arp_header*
            struct arp_header *arp_hdr = (struct arp_header *)((void *)buf +
                                                               sizeof(struct ether_header));
            if (arp_hdr->op == ntohs(ARPOP_REQUEST))
            { // request
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ARP_LEN);
                get_interface_mac(interface, eth_hdr->ether_shost);

                memcpy(arp_hdr->tha, arp_hdr->sha, ETH_ARP_LEN);

                arp_hdr->tpa = arp_hdr->spa;
                arp_hdr->spa = inet_addr(get_interface_ip(interface));

                get_interface_mac(interface, arp_hdr->sha);
                // setare tip reply
                arp_hdr->op = htons(ARPOP_REPLY);

                send_to_link(interface, buf, len);
                continue;
            }
            else if (arp_hdr->op == ntohs(ARPOP_REPLY))
            { // reply
                reply_arp(arp_hdr, q);
                continue;
            }
            break;
        default:
            // Invalid protocol used for ethertype
            continue;
            break;
        }
    }
}
