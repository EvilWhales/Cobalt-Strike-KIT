#include "parser.h"

int is_port_valid(int p) {
    return MIN_PORT <= p && p <= MAX_PORT;
}

int is_ip_valid(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

// arbitrary but if you overflow 
// that's cause you're an idiot and shot yourself in the foot
#define IP_BUFFER_LEN 256

int is_iprange_valid(const char * input) {
    char ip_start[IP_BUFFER_LEN], ip_end[IP_BUFFER_LEN];

    sscanf(input, "%[^-]-%s", ip_start, ip_end);

    return is_ip_valid(ip_start) && is_ip_valid(ip_end);
}

HstIPRange* generate_ips_from_cidr(const char *cidr) {
    char ip[INET_ADDRSTRLEN];
    unsigned int prefix_len;

    sscanf(cidr, "%[^/]/%u", ip, &prefix_len);

    struct in_addr start_addr;
    if (inet_pton(AF_INET, ip, &start_addr) != 1) {
        fprintf(stderr, "[!] Invalid CIDR base address: %s\n", ip);
        return NULL;
    }

    uint32_t base = ntohl(start_addr.s_addr);
    uint32_t mask = ~((1 << (32 - prefix_len)) - 1);
    base &= mask;
    uint32_t range = (1 << (32 - prefix_len));

    struct in_addr end_addr;
    end_addr.s_addr = htonl(base + range - 1);

    HstIPRange * ret = (HstIPRange *)malloc(sizeof(HstIPRange));
    ret->start_addr = start_addr;
    ret->end_addr = end_addr;

    return ret;
}

HstIPRange* generate_ips_from_range(const char *range) {
    char start_ip[INET_ADDRSTRLEN], end_ip[INET_ADDRSTRLEN];

    sscanf(range, "%[^-]-%s", start_ip, end_ip);

    struct in_addr start_addr, end_addr;
    if (inet_pton(AF_INET, start_ip, &start_addr) != 1 || inet_pton(AF_INET, end_ip, &end_addr) != 1) {
        fprintf(stderr, "[!] Invalid range: %s\n", range);
        return NULL;
    }

    HstIPRange * ret = (HstIPRange *)malloc(sizeof(HstIPRange));

    // switch them around if the start is bigger than the end ip
    if (ntohl(start_addr.s_addr) < ntohl(end_addr.s_addr)) {
        ret->start_addr = start_addr;
        ret->end_addr = end_addr;
    } else {
        ret->start_addr = end_addr;
        ret->end_addr = start_addr;
    }

    return ret;
}

HstIPHost * generate_ips_from_iphost(char *input) {
    struct addrinfo hints, *res;
    char ipStr[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));

    //hints.ai_family = AF_UNSPEC;  // Support both IPv4 and IPv6
    hints.ai_family = AF_INET;  // only support IPv4 atm
    hints.ai_socktype = SOCK_STREAM;  // Stream socket (not required for resolution)

    int status = getaddrinfo(input, NULL, &hints, &res);
    if (status != 0) {
        //printf("[!] Failed to getaddrinfo. s: %d\n", status);
        return NULL;
    }

    // freeaddrinfo(res); // we're keeping it cause we need it for later
    HstIPHost * ret = (HstIPHost *)malloc(sizeof(HstIPHost));
    ret->res = res;
    ret->name = input;

    return ret;
}

Hst* parse_hosts(char *input) {
    Hst * ret = NULL;
    Hst * current = NULL;

    char *token = strtok(input, ",");

    do { 
        void * hst;
        HstInputType type = HIT_UNK;

        // a dash could also be a host, hence why we check if valid range
        if ((strchr(token, '-') != NULL) && is_iprange_valid(token)) {
            hst = (void *)generate_ips_from_range(token);
            type = HIT_RANGE;
            if (hst == NULL) {
                printf("[!] Couldn't parse range: %s\n", token);
                continue;
            }
        } else if (strchr(token, '/') != NULL) {
            hst = (void *)generate_ips_from_cidr(token);
            type = HIT_RANGE;
            if (hst == NULL) {
                printf("[!] Couldn't parse cidr: %s\n", token);
                continue;
            }
        } else {
            // this should either be an IP or a hostname
            // so we can use getaddrinfo here
            hst = (void *)generate_ips_from_iphost(token);
            type = HIT_IPHOST;
            if (hst == NULL) {
                printf("[!] Couldn't parse ip/host: %s\n", token);
                continue;
            }
        }

        if (hst == NULL || type == HIT_UNK) {
            // something went wrong?
            // this shouldnt happen tbh but gonna leave it here for now
            printf("[!] Couldn't parse input: %s\n", token);
            continue;
        }

        if (ret == NULL) {
            ret = (Hst *)malloc(sizeof(Hst));
            ret->type = type;
            ret->hst = hst;
            ret->next = NULL;

            current = ret;
            continue;
        }

        current->next = (Hst *)malloc(sizeof(Hst));
        current = current->next;
        current->type = type;
        current->hst = hst;
        current->next = NULL;

    } while ((token = strtok(NULL, ",")) != NULL);

    return ret;
}

Prt* parse_ports(char *input) {
    Prt * first_port = NULL;
    Prt * current = NULL;

    char *token = strtok(input, ",");
    while (token != NULL) {
        unsigned int start_port, end_port;

        if (strchr(token, '-') != NULL) {
            // port range
            if (!sscanf(token, "%d-%d", &start_port, &end_port)
                || !(is_port_valid(start_port) && is_port_valid(end_port))) {
                printf("[!] wrong input provided: %s\n", token);
                continue;
            }
        } else {
            // single port
            if (!sscanf(token, "%d", &start_port)
                || !is_port_valid(start_port)) {
                printf("[!] wrong input provided: %s\n", token);
                continue;
            }
            end_port = start_port;
        }

        if (end_port < start_port) {
            unsigned int tmp;
            tmp = end_port;
            end_port = start_port;
            start_port = tmp;
        }

        token = strtok(NULL, ",");

        if (first_port == NULL) { 
            first_port = (Prt *)malloc(sizeof(Prt));
            current = first_port;
            current->start = start_port;
            current->end = end_port;
            current->next = NULL;
            continue;
        }

        current->next = (Prt *)malloc(sizeof(Prt));
        current = current->next;
        current->start = start_port;
        current->end = end_port;
        current->next = NULL;
    }

    return first_port;
}

void print_hosts(Hst* hosts) {
    Hst* c;
    c = hosts;

    do {
        if (c->type == HIT_RANGE) {
            HstIPRange *r = (HstIPRange*)c->hst;

            char buf1[INET_ADDRSTRLEN];
            char buf2[INET_ADDRSTRLEN];
            printf("[IP range] %s | %s\n", 
                   inet_ntop(AF_INET, &r->start_addr, buf1, INET_ADDRSTRLEN),
                   inet_ntop(AF_INET, &r->end_addr, buf2, INET_ADDRSTRLEN)
            );
        } else if (c->type == HIT_IPHOST) {
            HstIPHost *r = (HstIPHost*)c->hst;
            char ipStr[INET_ADDRSTRLEN];

            for (struct addrinfo *p = r->res; p != NULL; p = p->ai_next) {
                void *addr;
                if (p->ai_family == AF_INET) {  // IPv4
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                    addr = &(ipv4->sin_addr);
                } else {
                    continue;
                }

                inet_ntop(p->ai_family, addr, ipStr, sizeof(ipStr));
                printf("[Host/IP] %s | %s\n", r->name, ipStr);
            }
        }
    } while((c = c->next) != NULL);
}

void print_ports(Prt* ports) {
    Prt* p= ports;
    while(p != NULL) {
        printf("[PORT] %u | %u\n",p->start,p->end);
        p = p->next;
    }
}

void free_hosts(Hst *host){
    if(host == NULL) return;

    free_hosts(host->next);

    if (host->type == HIT_RANGE) {
        free(host->hst);
    } else if (host->type == HIT_IPHOST) {
        freeaddrinfo(((HstIPHost*)host->hst)->res);
        free(host->hst);
    }
    free(host);
}

void free_ports(Prt *port){
    if(port == NULL) return;

    free_ports(port->next);
    free(port);
}

#ifdef PARSER_MAIN

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <hosts> <ports>\n", argv[0]);
        return 1;
    }

    Hst* h = parse_hosts(argv[1]);

    puts("[HOSTS]");
    print_hosts(h);

    Prt* p = parse_ports(argv[2]);

    puts("[PORTS]");
    print_ports(p);

    return 0;
}

#endif /* ifdef PARSER_MAIN */
