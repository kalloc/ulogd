/* ulogd_SENSOR.c, Version $Revision$
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
#include <search.h>
#include <pthread.h>
#include "aes.h"

int workaholic=1;

////////////////////////////////////////////////////////////////
//aes
////////////////////////////////////////////////////////////////
aes_context ctx;

////////////////////////////////////////////////////////////////
//config
////////////////////////////////////////////////////////////////
#define MAXBUF 1024
struct intr_id {
	char* name;
	unsigned int id;		
};
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
#define GET_ICMP_TYPE   GET_VALUE(28).ui16
#define GET_ICMP_CODE   GET_VALUE(29).ui16
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

#define DEBUG 1

#define GET_VALUE(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].value
#define GET_FLAGS(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].flags
#define ULOGD_SENSOR_DEFAULT_HOST "127.0.0.1"
#define ULOGD_SENSOR_DEFAULT_PORT 5555

static config_entry_t host_ce = { 
    .key = "host", 
    .type = CONFIG_TYPE_STRING, 
    .options = CONFIG_OPT_NONE, 
	.u = { .string = ULOGD_SENSOR_DEFAULT_HOST } 
};

static config_entry_t pass_ce = { 
    .next = &host_ce, 
    .key = "pass", 
    .type = CONFIG_TYPE_STRING, 
    .options = CONFIG_OPT_NONE, 
	.u = { .string = NULL }
};

static config_entry_t period_ce = { 
    .next = &pass_ce, 
    .key = "period", 
    .type = CONFIG_TYPE_INT, 
    .options = CONFIG_OPT_NONE, 
	.u = { .value = 60 }
};
static config_entry_t port_ce = { 
    .next = &period_ce, 
    .key = "port", 
    .type = CONFIG_TYPE_INT, 
    .options = CONFIG_OPT_NONE, 
	.u = { .value = ULOGD_SENSOR_DEFAULT_PORT }
};

////////////////////////////////////////////////////////////////
//Packet
////////////////////////////////////////////////////////////////
#pragma pack(push,1)
struct pkt {
    time_t time;
    char protocol;
    unsigned source_ip;
    unsigned destination_ip;
    unsigned short source_port;
    unsigned short destination_port;
    int len;
};

struct PacketListEntry {
    struct pkt pkt;
    SLIST_ENTRY(PacketListEntry) entries; /* List. */
};
#pragma pack(pop)
////////////////////////////////////////////////////////////////
//Report
////////////////////////////////////////////////////////////////
struct ReportListEntry {
    char order[32];
    SLIST_HEAD(PacketListHead, PacketListEntry) PacketHead;
    SLIST_ENTRY(ReportListEntry) entries; /* List. */
} *report;


////////////////////////////////////////////////////////////////
//Server
////////////////////////////////////////////////////////////////
struct Server {
    FILE * file;
    struct in_addr ip;
    int port;
    int fd;
    struct sockaddr_in sa;
    char *host;
    void *report_root;
    pthread_mutex_t *mutex;
    SLIST_HEAD(ReportListHead, ReportListEntry) ReportHead;
    SLIST_ENTRY(Server) entries;
};
SLIST_HEAD(ServerListHead, Server) ServerHead;
////////////////////////////////////////////////////////////////
static pthread_mutex_t  *local_mutex = NULL;

int report_cmp(const void *a, const void *b) {
  struct ReportListEntry *left, *right;
  left = (struct ReportListEntry *)a;
  right = (struct ReportListEntry *)b;
  return strcmp(left->order, right->order);
}



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
void process_sender(struct Server *to,struct ReportListEntry *report) {
    int fd, ret;
    unsigned len = 0;
    char buf[MAXBUF];
    struct PacketListEntry * packet;
    char aes_iv[16];

    bzero(buf, MAXBUF);
    if(SLIST_EMPTY(&report->PacketHead)) return;
    SLIST_FOREACH(packet, &report->PacketHead, entries) {
        if(len == 0) {
            buf[16]='O';
            buf[17]='K';
            memcpy(buf+18, report->order,  sizeof(report->order));
            len=18+sizeof(report->order);
        }
        
        memcpy(buf+len,&packet->pkt,sizeof(struct pkt));
        len+=sizeof(struct pkt);
        if(len+sizeof(struct pkt)>MAXBUF) {
            if(pass_ce.u.string) {
                fread(&aes_iv, 16, 1, to->file);
                memcpy(buf, aes_iv, 16);
                len = aes_cbc_encrypt(&ctx, aes_iv, buf+16, buf+16, len-16) + 16;
            } 
            ret = sendto(to->fd, &buf, len, 0,(struct sockaddr*)&to->sa, sizeof to->sa);
            len=0;
        }

        SLIST_REMOVE(&report->PacketHead, packet, PacketListEntry, entries);
        free(packet);
    }
    if(len>0) {
        if(pass_ce.u.string) {
            fread(&aes_iv, 16, 1, to->file);
            memcpy(buf, aes_iv, 16);
            len = aes_cbc_encrypt(&ctx, aes_iv, buf+16, buf+16, len-16)+16;
        } 
        sendto(to->fd, &buf, len, 0,(struct sockaddr*)&to->sa, sizeof to->sa);
        len=0;
    }
}


static void prepare_sender(void *arg) {
    struct Server *server = (struct Server *) arg;
    struct PacketListEntry * packet;
    struct ReportListEntry * report;
    server->file=fopen("/dev/urandom", "r");
    while(workaholic) {
        if(!SLIST_EMPTY(&server->ReportHead)) {
            SLIST_FOREACH(report, &server->ReportHead, entries) {

                pthread_mutex_lock(server->mutex);
                process_sender(server, report);
                pthread_mutex_lock(local_mutex);
                SLIST_REMOVE(&server->ReportHead, report, ReportListEntry, entries);
                tdelete(report, &server->report_root, report_cmp);
                free(report);
                pthread_mutex_unlock(local_mutex);
                pthread_mutex_unlock(server->mutex);

            }
        }
        sleep(period_ce.u.value);
    }
    fclose(server->file);
    SLIST_FOREACH(report, &server->ReportHead, entries) {
        pthread_mutex_lock(server->mutex);
        SLIST_FOREACH(packet, &report->PacketHead, entries) {
            SLIST_REMOVE(&report->PacketHead, packet, PacketListEntry, entries);
            free(packet);
        }
        tdelete(report, &server->report_root, report_cmp);
        SLIST_REMOVE(&server->ReportHead, report, ReportListEntry, entries);
        free(report);
        pthread_mutex_unlock(server->mutex);
        free(server);
    }
}
void start_sender(char *host, int port) {

    pthread_t threads;
    struct Server * server = malloc(sizeof(struct Server));
    bzero(server, sizeof(struct Server));
    server->mutex = calloc(1, sizeof (*server->mutex));
    pthread_mutex_init(server->mutex, NULL);
    server->host=strdup(host);
    inet_aton(host,&server->ip);
    server->port=port;
    server->fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    server->sa.sin_family = AF_INET;
    server->sa.sin_addr = server->ip;
    server->sa.sin_port = htons(server->port);
    SLIST_INIT(&server->ReportHead);
    SLIST_INSERT_HEAD(&ServerHead, server, entries);
    pthread_create(&threads, NULL, (void*) prepare_sender, server);

}

static int _output(ulog_iret_t *res)
{

    if(GET_IP_PROTOCOL != IPPROTO_TCP && GET_IP_PROTOCOL != IPPROTO_UDP) return 0;
    struct ReportListEntry *report, *ptr_report;
    struct PacketListEntry *packet = malloc(sizeof(struct PacketListEntry)), *ptr_packet;
    struct Server *server = NULL;
    bzero(packet, sizeof(struct PacketListEntry));  
    packet->pkt.time  = (time_t) GET_OOB_TIME_SEC;;
    packet->pkt.protocol = GET_IP_PROTOCOL;
    packet->pkt.len = GET_IP_TOTLEN;
    packet->pkt.source_ip = htonl(GET_IP_SADDR);
    packet->pkt.destination_ip = htonl(GET_IP_DADDR);

    switch (GET_IP_PROTOCOL) {
        case IPPROTO_TCP:
            packet->pkt.source_port = GET_TCP_SPORT;
            packet->pkt.destination_port = GET_TCP_DPORT;
            break;
        case IPPROTO_UDP:
            packet->pkt.source_port = GET_UDP_SPORT;
            packet->pkt.destination_port = GET_UDP_DPORT;
            break;
        case IPPROTO_ICMP:
            packet->pkt.source_port = GET_ICMP_TYPE;
            packet->pkt.destination_port = GET_ICMP_CODE;
            break;
    }
#ifdef DEBUG
    printf("[%s] %d %s:%d -[proto %08x]-> %s:%d %d bytes\n",(char *)GET_OOB_PREFIX, packet->pkt.time, 
            packet->pkt.protocol,
		    inet_ntoa((struct in_addr) {packet->pkt.source_ip}), packet->pkt.source_port,
		    inet_ntoa((struct in_addr) {packet->pkt.destination_ip}), packet->pkt.destination_port,
            packet->pkt.len);
#endif

    SLIST_FOREACH(server, &ServerHead, entries) {
        ptr_packet = malloc(sizeof(struct PacketListEntry));
        memcpy(ptr_packet, packet, sizeof(struct PacketListEntry));
        report = malloc(sizeof(struct ReportListEntry));
        bzero(report, sizeof(struct ReportListEntry));
        pthread_mutex_lock(server->mutex);
        memcpy(report->order,(char *)GET_OOB_PREFIX,sizeof(report->order));
        ptr_report = tsearch(report, &server->report_root, report_cmp);
        if(*(void **)ptr_report == report) {
            SLIST_INSERT_HEAD(&server->ReportHead, report, entries);
            SLIST_INIT(&report->PacketHead);
        } else {
            free(report);
            report = *(void**)ptr_report;
        }
        SLIST_INSERT_HEAD(&report->PacketHead, ptr_packet, entries);
        pthread_mutex_unlock(server->mutex);
    }
    free(packet);

    return 0;
}


static void finish(void) {
    workaholic=0;
}

static int init(void) {
    char password[17]={0};
    get_ids();
    config_parse_file("SENSOR", &port_ce);
    if(pass_ce.u.string != NULL) {
        snprintf(password,17,"%s",pass_ce.u.string);
        aes_set_key(&ctx, password, 128);
    }
    return 1;
}

static int start(void) {
    char *ptr, *port_ptr, *host;
    char password[17]={0};

    unsigned int port_default, port, is_port=0;
    if (!local_mutex) {
        local_mutex = calloc(1, sizeof (*local_mutex));
        pthread_mutex_init(local_mutex, NULL);
    }
    SLIST_INIT(&ServerHead);
    host = ptr = host_ce.u.string;
    port_default = port_ce.u.value;
    while(*(ptr+1)!=0) {
        if(*ptr == ':')  {
            is_port = 1;
            *ptr = 0;
            port_ptr=++ptr;
        }
        else if(*ptr == ',' || *ptr == ' ') {
            *ptr = 0;
            if(is_port) {
                port=atoi(port_ptr);
                is_port = 0;
            } else {
                port = port_default;
            }
            start_sender(host, port);
            ptr++;
            host=ptr;
        }
        ptr++;
    }

    start_sender(host, port);
    return 1;
}

static ulog_output_t sensor_op = { 
    .name = "sensor",
    .init = &init,
    .start = &start,
    .fini = &finish,
    .output = &_output, 
};

void _init(void)
{
    register_output(&sensor_op);
}


