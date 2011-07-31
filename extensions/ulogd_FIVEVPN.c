/* ulogd_FIVEVPN.c, Version $Revision$
 *
 * (C) 2011 by kalloc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <pthread.h>

#define MAXBUF 1024
struct intr_id {
	char* name;
	unsigned int id;		
};
int workaholic=1;
#define INTR_IDS 	35
//easy idx
#define GET_OOB_TIME_SEC GET_VALUE(0).ui32
#define GET_OOB_PREFIX   GET_VALUE(1).ptr
#define GET_OOB_IN       GET_VALUE(2)
#define GET_OOB_OUT      GET_VALUE(3)
#define GET_RAW_MAC      GET_VALUE(4)
#define GET_IP_SADDR     GET_VALUE(5).ui32
#define GET_IP_DADDR     GET_VALUE(6).ui32
#define GET_IP_TOTLEN    GET_VALUE(7).ui16
#define GET_IP_TOS       GET_VALUE(8)
#define GET_IP_TTL       GET_VALUE(9)
#define GET_IP_ID       GET_VALUE(10)
#define GET_IP_FRAGOFF  GET_VALUE(11)
#define GET_IP_PROTOCOL GET_VALUE(12).ui8
#define GET_TCP_SPORT   GET_VALUE(13).ui16
#define GET_TCP_DPORT   GET_VALUE(14).ui16
#define GET_TCP_SEC     GET_VALUE(15)
#define GET_TCP_ACKSEQ  GET_VALUE(16)
#define GET_TCP_WINDOW  GET_VALUE(17)
#define GET_TCP_URG     GET_VALUE(18)
#define GET_TCP_ACL     GET_VALUE(19)
#define GET_TCP_PSH     GET_VALUE(20)
#define GET_TCP_RST     GET_VALUE(21)
#define GET_TCP_SYN     GET_VALUE(22)
#define GET_TCP_FIN     GET_VALUE(23)
#define GET_TCP_URGP    GET_VALUE(24)
#define GET_UDP_SPORT   GET_VALUE(25).ui16
#define GET_UDP_DPORT   GET_VALUE(26).ui16
#define GET_UDP_LEM     GET_VALUE(27)
#define GET_ICMP_TYPE   GET_VALUE(28)
#define GET_ICMP_CODE   GET_VALUE(29)
#define GET_ICMP_ECHOID GET_VALUE(30)
#define GET_ICMP_ECHOSEQ GET_VALUE(31)
#define GET_ICMP_GATEWAY GET_VALUE(32)
#define GET_ICMP_FRAGMTU GET_VALUE(33)
#define GET_AHESP_SPI   GET_VALUE(34)


static struct intr_id intr_ids[INTR_IDS] = {
	{ "oob.time.sec", 0 },
	{ "oob.prefix", 0 },  
	{ "oob.in", 0 },
	{ "oob.out", 0 },
	{ "raw.mac", 0 },
	{ "ip.saddr", 0 },
	{ "ip.daddr", 0 },
	{ "ip.totlen", 0 },
	{ "ip.tos", 0 },
	{ "ip.ttl", 0 },
	{ "ip.id", 0 },
	{ "ip.fragoff", 0 },
	{ "ip.protocol", 0 },
	{ "tcp.sport", 0 },
	{ "tcp.dport", 0 },
	{ "tcp.seq", 0 },
	{ "tcp.ackseq", 0 },
	{ "tcp.window", 0 },
	{ "tcp.urg", 0 },
	{ "tcp.ack", 0 },
	{ "tcp.psh", 0 },
	{ "tcp.rst", 0 },
	{ "tcp.syn", 0 },
	{ "tcp.fin", 0 },
	{ "tcp.urgp", 0 },
	{ "udp.sport", 0 },
	{ "udp.dport", 0 },
	{ "udp.len", 0 },
	{ "icmp.type", 0 },
	{ "icmp.code", 0 },
	{ "icmp.echoid", 0 },
	{ "icmp.echoseq", 0 },
	{ "icmp.gateway", 0 },
	{ "icmp.fragmtu", 0 },
	{ "ahesp.spi", 0 },
};

#define GET_VALUE(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].value
#define GET_FLAGS(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].flags
#define ULOGD_FIVEVPN_DEFAULT_HOST "127.0.0.1"
#define ULOGD_FIVEVPN_DEFAULT_PORT 5555

//dump
#pragma pack (push, 1)
struct pkt {
    time_t time;
    char order[31];
    char protocol;
    struct ip {
        unsigned source;
        unsigned destination;
    } ip;
    unsigned short sport;
    unsigned short dport;
    int len;
};
#pragma push

struct DumpListEntry {
    struct pkt pkt;
    int link;
    SLIST_ENTRY(DumpListEntry) entries; /* List. */
};

//Servers
struct Server {
    struct in_addr ip;
    int port;
    pthread_t thread_id;        /* ID returned by pthread_create() */
    SLIST_HEAD(DumpListHead, DumpListEntry) DumpHead;
    SLIST_ENTRY(Server) entries; /* List. */
} *server;

static pthread_mutex_t *mutex = NULL;

SLIST_HEAD(ServerListHead, Server) ServerHead;



//somefunction

static int get_ids(void) {
    int i;
    struct intr_id *cur_id;

    for (i = 0; i < INTR_IDS; i++) {
        cur_id = &intr_ids[i];
        cur_id->id = keyh_getid(cur_id->name);
        if (!cur_id->id) {
            ulogd_log(ULOGD_ERROR, 
                    "Cannot resolve keyhash id for %s\n", 
                    cur_id->name);
            return 1;
        }
    }	
    return 0;
}

static void process_sender(void *arg) {
    struct DumpListEntry *dump;
    struct sockaddr_in sa;
    int fd, ret;
    struct Server *server = (struct Server *) arg;
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sa.sin_family = AF_INET;
    sa.sin_addr = server->ip;
    sa.sin_port = htons(server->port);


    while(workaholic) {
        SLIST_FOREACH(dump, &server->DumpHead, entries) {
            ret = sendto(fd, &dump->pkt, sizeof(struct pkt), 0,(struct sockaddr*)&sa, sizeof sa);
            pthread_mutex_lock(mutex);
            SLIST_REMOVE(&server->DumpHead, dump, DumpListEntry, entries);
            dump->link--;
            if(dump->link == 0) {
                free(dump);
            }
            pthread_mutex_unlock(mutex);
        }
        sleep(1);
    }

}
void start_sender(char *host, int port) {
    printf("start sender to %s:%d\n", host, port);
    pthread_t threads;
    server = malloc(sizeof(struct Server));
    inet_aton(host,&server->ip);
    server->port=port;
    SLIST_INIT(&server->DumpHead);
    SLIST_INSERT_HEAD(&ServerHead, server, entries);
    pthread_create(&threads, NULL, (void*) process_sender, server);
}

static int _output(ulog_iret_t *res)
{

    if(GET_IP_PROTOCOL != IPPROTO_TCP && GET_IP_PROTOCOL != IPPROTO_UDP) return 0;
    struct DumpListEntry *entry  = malloc(sizeof(struct DumpListEntry));
    bzero(entry, sizeof(struct DumpListEntry));  
    
    entry->pkt.time  = (time_t) GET_OOB_TIME_SEC;;
    memcpy(entry->pkt.order,(char *)GET_OOB_PREFIX,sizeof(entry->pkt.order));
    entry->pkt.protocol = GET_IP_PROTOCOL;
    entry->pkt.len = GET_IP_TOTLEN;
    entry->pkt.ip.source = htonl(GET_IP_SADDR);
    entry->pkt.ip.destination = htonl(GET_IP_DADDR);
    switch (GET_IP_PROTOCOL) {
        case IPPROTO_TCP:
            entry->pkt.sport = GET_TCP_SPORT;
            entry->pkt.dport = GET_TCP_DPORT;
            break;
        case IPPROTO_UDP:
            entry->pkt.sport = GET_UDP_SPORT;
            entry->pkt.dport = GET_UDP_DPORT;
            break;
    }
#ifdef DEBUG
    printf("[%s] %d %s:%d -> %s:%d %d bytes\n",entry->pkt.order, entry->pkt.time, 
		    inet_ntoa((struct in_addr) {entry->pkt.ip.source}), entry->pkt.sport,
		    inet_ntoa((struct in_addr) {entry->pkt.ip.destination}), entry->pkt.dport,
            entry->pkt.len);
#endif
    SLIST_FOREACH(server, &ServerHead, entries) {
        pthread_mutex_lock(mutex);
        SLIST_INSERT_HEAD(&server->DumpHead, entry, entries);
        pthread_mutex_unlock(mutex);
        entry->link++;
    }

    return 0;
}


static void finish(void) {
    workaholic=0;
}
static config_entry_t host_ce = { 
    .key = "host", 
    .type = CONFIG_TYPE_STRING, 
    .options = CONFIG_OPT_NONE, 
	.u = { .string = ULOGD_FIVEVPN_DEFAULT_HOST } 
};

static config_entry_t port_ce = { 
    .next = &host_ce, 
    .key = "port", 
    .type = CONFIG_TYPE_INT, 
    .options = CONFIG_OPT_NONE, 
	.u = { .value = ULOGD_FIVEVPN_DEFAULT_PORT }
};

static int init(void) {
    char *ptr,*host;
    if (!mutex) {
        mutex = calloc(1, sizeof (*mutex));
        pthread_mutex_init(mutex, NULL);
    }
    SLIST_INIT(&ServerHead);
    get_ids();
    config_parse_file("FIVEVPN", &port_ce);
    host = ptr = host_ce.u.string;
    while(*(ptr++)!=0) {
        if(*ptr == ',' || *ptr == ' ') {
            *ptr=0;
            start_sender(host, port_ce.u.value);
            host=ptr+1;
        }
    }
    start_sender(host, port_ce.u.value);
    return 1;
}

static ulog_output_t fivevpn_op = { 
    .name = "fivevpn",
    .init = &init,
    .fini = &finish,
    .output = &_output, 
};

void _init(void)
{
    register_output(&fivevpn_op);
}


