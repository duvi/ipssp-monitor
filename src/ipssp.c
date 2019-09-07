/*
 * ipssp.c - A simply radiotap capture utility outputting pcap dumps
 *
 *    Copyright 2012 Jo-Philipp Wich <jo@mein.io>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <math.h>

#include "ipssp.h"

#define ARPHRD_IEEE80211_RADIOTAP	803

#define DLT_IEEE802_11_RADIO		127
#define LEN_IEEE802_11_HDR			32

#define FRAMETYPE_MASK				0xFC
#define FRAMETYPE_BEACON			0x80
#define FRAMETYPE_DATA				0x08

#if __BYTE_ORDER == __BIG_ENDIAN
#define le16(x) __bswap_16(x)
#else
#define le16(x) (x)
#endif


#if defined(HAVE_ATH9K)
#define IPSSP_CHANNEL_BYTE_1 26
#define IPSSP_CHANNEL_BYTE_2 27
#define IPSSP_SIGNAL_BYTE 30
#endif

#if defined(HAVE_MT76X2)
#define IPSSP_CHANNEL_BYTE_1 18
#define IPSSP_CHANNEL_BYTE_2 19
#define IPSSP_SIGNAL_BYTE 22
#endif


typedef struct ieee802_11_hdr {
  u_char frame_control;
#define IEEE80211_DATA 0x08
  u_char flags;
#define IEEE80211_TO_DS 0x01
#define IEEE80211_FROM_DS 0x02
#define IEEE80211_MORE_FRAG 0x04
#define IEEE80211_RETRY 0x08
#define IEEE80211_PWR_MGT 0x10
#define IEEE80211_MORE_DATA 0x20
#define IEEE80211_WEP_FLAG 0x40
#define IEEE80211_ORDER_FLAG 0x80
  u_short duration;
  u_char addr1[6];
  u_char addr2[6];
  u_char addr3[6];
  u_short frag_and_seq;
  u_char addr4[6];
  } ieee802_11_hdr;

uint8_t run_dump   = 0;
uint8_t run_stop   = 0;
uint8_t run_daemon = 0;

uint32_t frames_captured = 0;
uint32_t frames_filtered = 0;

int capture_sock = -1;
char *ifname = NULL;


struct ringbuf {
	uint32_t len;            /* number of slots */
	uint32_t fill;           /* last used slot */
	uint32_t slen;           /* slot size */
	void *buf;               /* ring memory */
};

struct ringbuf_entry {
	uint32_t len;            /* used slot memory */
	uint32_t olen;           /* original data size */
	uint32_t sec;            /* epoch of slot creation */
	uint32_t usec;			 /* epoch microseconds */
};

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ieee80211_radiotap_header {
	u_int8_t  it_version;    /* set to 0 */
	u_int8_t  it_pad;
	u_int16_t it_len;        /* entire length */
	u_int32_t it_present;    /* fields present */
#define RADIOTAP_TSFT 0x01
#define RADIOTAP_FLAGS 0x02
#define RADIOTAP_RATE 0x04
#define RADIOTAP_CHANNEL 0x08
#define RADIOTAP_FHSS 0x10
#define RADIOTAP_SIGNAL 0x20
#define RADIOTAP_NOISE 0x40
#define RADIOTAP_LOCK 0x80
} __attribute__((__packed__)) radiotap_hdr_t;


int check_type(void)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(capture_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;

	return (ifr.ifr_hwaddr.sa_family == ARPHRD_IEEE80211_RADIOTAP);
}

int set_promisc(int on)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(capture_sock, SIOCGIFFLAGS, &ifr) < 0)
		return -1;

	if (on && !(ifr.ifr_flags & IFF_PROMISC))
	{
		ifr.ifr_flags |= IFF_PROMISC;

		if (ioctl(capture_sock, SIOCSIFFLAGS, &ifr))
			return -1;

		return 1;
	}
	else if (!on && (ifr.ifr_flags & IFF_PROMISC))
	{
		ifr.ifr_flags &= ~IFF_PROMISC;

		if (ioctl(capture_sock, SIOCSIFFLAGS, &ifr))
			return -1;

		return 1;
	}

	return 0;
}


void sig_dump(int sig)
{
	run_dump = 1;
}

void sig_teardown(int sig)
{
	run_stop = 1;
}

void msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (run_daemon)
		vsyslog(LOG_INFO | LOG_USER, fmt, ap);
	else
		vfprintf(stderr, fmt, ap);

	va_end(ap);
}

void fprint_mac(FILE * outf, u_char * mac, char * extra) {
  fprintf(outf, "%02X:%02X:%02X:%02X:%02X:%02X%s",
      mac[0] & 0xFF,
      mac[1] & 0xFF,
      mac[2] & 0xFF,
      mac[3] & 0xFF,
      mac[4] & 0xFF,
      mac[5] & 0xFF,
      extra);
}

void print_mac(u_char * mac, char * extra) {
  fprint_mac(stdout, mac, extra);
  }

int get_mac(char *name, void *buf)
{
	struct ifreq ifr;
	int ret = 0;
 	int s;

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return errno;
	}

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	//ifr.ifr_data = (caddr_t) buf;
	if ((ret = ioctl(s, SIOCGIFHWADDR, &ifr)) < 0)
			perror(ifr.ifr_name);

	/* cleanup */
	close(s);
	memcpy(buf, &ifr.ifr_hwaddr.sa_data, 6);
	return ret;
}

void open_out(char *host, int port)
{
    struct hostent *he;

    if ((he=gethostbyname(host)) == NULL)		// veszi a hosztinformációt
	{
	perror("gethostbyname");
	exit(1);
	}

    if ((sockfd_out = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
	perror("socket");
	exit(1);
	}

    server_addr.sin_family = AF_INET;		// host byte order
    server_addr.sin_port = htons(port);		// short, network byte order
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(&(server_addr.sin_zero), '\0', 8);	// kinullázza a struktúra maradék részét
}

void elkuld(char ki_adat[40], int length)
{
    if ((numbytes_out=sendto(sockfd_out, ki_adat, length, 0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr))) == -1)
	{
	perror("sendto");
	exit(1);
	}
}

#define OFFSET 0
u_int ieee80211_mhz2ieee( u_int freq )
{
    if( freq == 2484 + OFFSET )
	return 14;
    if( freq < 2484 + OFFSET )
	return ( freq - ( 2407 + OFFSET ) ) / 5;
    if( freq < 4990 && freq > 4940 )
	return ( ( freq * 10 ) + ( ( ( freq % 5 ) == 2 ) ? 5 : 0 ) -
		 49400 ) / 5;
    if( freq < 5000 )
	return 15 + ( ( freq - ( 2512 + OFFSET ) ) / 20 );

    return ( freq - ( 5000 + OFFSET ) ) / 5;
}

double dbm2mw(int sig_db)
{
	double sig_mw;
	sig_mw = pow(10.0, ((sig_db) / 10.0));
	return sig_mw;
}

int mw2dbm(double sig_mw)
{
	int sig_db;
	sig_db = 10 * log10(sig_mw);
	return sig_db;
}


int main(int argc, char **argv)
{
	int i, n;
	struct sockaddr_ll local = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL)
	};

	radiotap_hdr_t *rhdr;
	ieee802_11_hdr *header;

	int to_ds, from_ds, data, signal_present;
	char * src = "\0\0\0\0\0\0";
	char * dst = "\0\0\0\0\0\0";
	int in_signal;
	int in_channel;
	u_char in_mac[6];

	uint8_t frametype;
	uint8_t pktbuf[0xFFFF];
	ssize_t pktlen;

	int opt;

	uint8_t promisc    = 0;
	uint8_t streaming  = 0;
	uint8_t foreground = 0;
	uint8_t text       = 0;

	while ((opt = getopt(argc, argv, "i:r:p:sfht")) != -1)
	{
		switch (opt)
		{
		case 'i':
			ifname = optarg;
			if (!(local.sll_ifindex = if_nametoindex(ifname)))
			{
				msg("Unknown interface '%s'\n", ifname);
				return 2;
			}
			break;

		case 's':
			streaming = 1;
			break;

		case 'f':
			foreground = 1;
			break;

		case 't':
			text = 1;
			break;

		case 'r':
			remote = optarg;
			break;

		case 'p':
			port = atoi(optarg);
			break;

		case 'h':
			msg(
				"Usage:\n"
				"  %s -i {iface} -s [-f]\n"
				"  %s -i {iface} -r {hostname} -p {port} [-f]\n"
				"\n"
				"  -i iface\n"
				"    Specify interface to use, must be in monitor mode and\n"
				"    produce IEEE 802.11 Radiotap headers.\n\n"
				"  -r hostname\n"
				"    Specify the remote hostname to send the packets to.\n\n"
				"  -p port\n"
				"    Specify the listening port in the remote host.\n\n"
				"  -s\n"
				"    Stream to stdout instead of Dumping to file on USR1.\n\n"
				"  -f\n"
				"    Do not daemonize but keep running in foreground.\n\n"
				"  -t\n"
				"    Send data in human readable text.\n\n"
				"  -h\n"
				"    Display this help.\n\n",
				argv[0], argv[0]);

			return 1;
		}
	}

	get_mac(ifname, serial_address);

	if (!streaming && (!remote || !port))
	{
		msg("No server or port specified\n");
		return 1;
	}

	if (!local.sll_ifindex)
	{
		msg("No interface specified\n");
		return 2;
	}

	if (!check_type())
	{
		msg("Bad interface: not ARPHRD_IEEE80211_RADIOTAP\n");
		return 2;
	}

	if ((capture_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		msg("Unable to create raw socket: %s\n",
				strerror(errno));
		return 6;
	}

	if (bind(capture_sock, (struct sockaddr *)&local, sizeof(local)) == -1)
	{
		msg("Unable to bind to interface: %s\n",
			strerror(errno));
		return 7;
	}

	msg("Monitoring interface %s ...\n", ifname);
	msg("MAC address: "); print_mac(serial_address, "\n");

#if defined(HAVE_ATH9K)
	msg("Driver in use: ath9k\n");
#endif

#if defined (HAVE_MT76X2)
	msg("Driver in use: mt76x2\n");
#endif

	if (!streaming)
	{
		if (!foreground)
		{
			switch (fork())
			{
				case -1:
					msg("Unable to fork: %s\n", strerror(errno));
					return 8;

				case 0:
					umask(0077);
					chdir("/");
					freopen("/dev/null", "r", stdin);
					freopen("/dev/null", "w", stdout);
					freopen("/dev/null", "w", stderr);
					run_daemon = 1;
					break;

				default:
					msg("Daemon launched ...\n");
					return 0;
			}
		}

		signal(SIGUSR1, sig_dump);
	}
	else
	{
		msg(" * Streaming data to stdout\n");
	}

        if (remote && port)
        {
		msg(" * Sending data to host %s port %i \n", remote, port);
		open_out(remote, port);
        }

	signal(SIGINT, sig_teardown);
	signal(SIGTERM, sig_teardown);

	promisc = set_promisc(1);

	/* capture loop */
	while (1)
	{
		if (run_stop)
		{
			msg("Shutting down ...\n");

			if (promisc)
				set_promisc(0);

			return 0;
		}

		pktlen = recvfrom(capture_sock, pktbuf, sizeof(pktbuf), 0, NULL, 0);
		frames_captured++;

		if (pktbuf[0]>0) {
		    printf( "Wrong radiotap header version.\n" );
		    continue;
		}

		rhdr = (radiotap_hdr_t *) (pktbuf);
		signal_present = rhdr->it_present & RADIOTAP_SIGNAL;

		if (!signal_present) continue;

		int number = pktbuf[2] | (unsigned int)((unsigned int)pktbuf[3]<<8);
		if (number<=0 || number>=pktlen) {
		    printf("something wrong %d\n",number);
		    continue;
		}
		header = (ieee802_11_hdr *) (pktbuf + (number));

		to_ds = header->flags & IEEE80211_TO_DS;
		from_ds = header->flags & IEEE80211_FROM_DS;
		data = header->frame_control & IEEE80211_DATA;

		if (data) { //Data frame
		    if (!to_ds && !from_ds) {
			continue;
			src = header->addr2;
			dst = header->addr1;
			//bss = header->addr3;
		    }
		    if (!to_ds && from_ds) {
			continue;
			src = header->addr3;
			dst = header->addr1;
			//bss = header->addr2;
		    }
		    if (to_ds && !from_ds) {
			src = header->addr2;
			dst = header->addr3;
			//bss = header->addr1;
		    }
		    if (to_ds && from_ds) {
			continue;
			src = header->addr4;
			dst = header->addr3;
			//bss = header->addr1;
		    }
			memcpy(in_mac, src, 6);
			in_channel = ieee80211_mhz2ieee(pktbuf[IPSSP_CHANNEL_BYTE_2]*256 + pktbuf[IPSSP_CHANNEL_BYTE_1]);
			in_signal = (pktbuf[IPSSP_SIGNAL_BYTE]-256);

		}
		else {
		    continue;
		}

		if (streaming)
		{

			msg("fromDS:%d toDS:%d \n", from_ds, to_ds);
			msg("packet length: %d bytes\n", pktlen);
			printf("src: "); print_mac(src, "\n");
			printf("dst: "); print_mac(dst, "\n");
			printf("channel: %i\n", in_channel);
			printf("signal: %i\n", in_signal);
		}
		if (remote && port)
		{
		    p_temp = p_start;
		    csere = 0;

		    while (p_temp != NULL)
		        {
			    if ( (time(NULL) > p_temp->time) && (p_temp->counter != 0) )
			        {
			        if (time(NULL) == p_temp->time + 1)
				    {
				    if (streaming)
				        {
				        printf("sending. src: "); print_mac(p_temp->address, " "); printf("mon: "); print_mac(serial_address, " "); printf("sig: %i\n", (0-mw2dbm(p_temp->signal_mw / p_temp->counter)));
				        }
				    char adat_ki[40];
				    if (text)
					{
					sprintf(adat_ki, "pos_av %02x:%02x:%02x:%02x:%02x:%02x,%i,%i", p_temp->address[0] & 0xFF, p_temp->address[1] & 0xFF, p_temp->address[2] & 0xFF, p_temp->address[3] & 0xFF, p_temp->address[4] & 0xFF, p_temp->address[5] & 0xFF, (0-mw2dbm(p_temp->signal_mw / p_temp->counter)), p_temp->channel);
					elkuld(adat_ki, strlen(adat_ki));
					}
				    else
					{
					memcpy(adat_ki, serial_address, 6);
					memcpy(adat_ki+6, p_temp->address, 6);
					sprintf(adat_ki+12, "%c%c", (0-mw2dbm(p_temp->signal_mw / p_temp->counter)), p_temp->channel);
					elkuld(adat_ki, 14);
					}
				    }
				p_temp->signal_db = 0;
				p_temp->signal_mw = 0;
				p_temp->counter = 0;
				}
			    if (memcmp(in_mac, p_temp->address, 6) == 0)
				{
//				p_temp->signal_db += in_signal;
				p_temp->signal_mw += dbm2mw(in_signal);
				p_temp->channel = in_channel;
				p_temp->counter++;
				p_temp->time    = time(NULL);
				csere = 1;
				}
			    p_temp = p_temp->next;
			}
		     if (csere == 0)
		        {
			    p_new = (struct sender_list *) malloc(sizeof(struct sender_list));
				memcpy(p_new->address, in_mac ,6);
//				p_new->signal_db = in_signal;
				p_new->signal_mw = dbm2mw(in_signal);
				p_new->channel	 = in_channel;
				p_new->counter   = 1;
				p_new->time      = time(NULL);
				p_new->next	 = p_start;
				p_start		 = p_new;
			}


		}
		

	}

	return 0;
}
