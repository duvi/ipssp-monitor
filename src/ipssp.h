struct sender_list {
	unsigned char address[6];
	int signal_db;
	double signal_mw;
	int counter;
	int channel;
	time_t time;
	struct sender_list *next;
};

u_char serial_address[6];

struct sender_list *p_start = NULL;
struct sender_list *p_new, *p_temp;

int csere;

struct sockaddr_in server_addr;
int sockfd_out;
int numbytes_out;

char *remote = NULL;
int port;
