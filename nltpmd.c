/*
 * nltpmd.c
 * Source file for nltpmd
 * nltpmd (Netlink TPM daemon) is a netlink server used to recv the
 * IP packet from the network provenance kernel module and sign the
 * whole packet using TPM AIK and then send the signature, as well as
 * the packet itself back to the kernel moduel.
 * Dec 12, 2013 - Jan 7, 2014
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include "tpmw.h"
#include "nlm.h"

/* Global defs */
#define NLTPMD_NETLINK		77
#define NLTPMD_RECV_BUFF_LEN	1024*1024

/* Global variables */
extern char *optarg;
static struct sockaddr_nl nltpmd_nl_addr;
static struct sockaddr_nl nltpmd_nl_dest_addr;
static pid_t nltpmd_pid;
static int nltpmd_sock_fd;
static int use_fake_tpm_info;
static int debug_enabled;

/* Signal term handler */
static void nltpmd_signal_term(int signal)
{
	/* Close the socket */
	close(nltpmd_sock_fd);
	/* Close the TPM */
	tpmw_close_tpm();
}

/* Setup signal handler */
static int signals_init(void)
{
	int rc;
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	if ((rc = sigaddset(&sigmask, SIGTERM))) {
		printf("nltpmd - Error: sigaddset [%s]\n", strerror(errno));
		return -1;
	}

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = nltpmd_signal_term;
	if ((rc = sigaction(SIGTERM, &sa, NULL))) {
		printf("nltpmd - Error: signal SIGTERM not registered [%s]\n", strerror(errno));
		return -1;
	}

	return 0;
}

/* Init the netlink with initial nlmsg */
int nltpmd_init_netlink(void)
{
        struct nlmsghdr *nlh;
        struct iovec iov;
        struct msghdr msg;
        int rtn;
	char *init_msg = "hello_from_nltpmd";
	int init_msg_len = strlen(init_msg) + 1;

        // Init the stack struct to avoid potential error
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));

        // Create the nelink msg
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(init_msg_len));
        memset(nlh, 0, NLMSG_SPACE(init_msg_len));
        nlh->nlmsg_len = NLMSG_SPACE(init_msg_len);
        nlh->nlmsg_pid = nltpmd_pid;
        nlh->nlmsg_flags = 0;

	// Add the hello string into the msg
	strcpy(NLMSG_DATA(nlh), init_msg);

        // Nothing to do for test msg - it is already what it is
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;
        msg.msg_name = (void *)&nltpmd_nl_dest_addr;
        msg.msg_namelen = sizeof(nltpmd_nl_dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Send the msg to the kernel
        rtn = sendmsg(nltpmd_sock_fd, &msg, 0);
        if (rtn == -1)
        {
                printf("nltpmd_init_netlink: Error on sending netlink init msg to the kernel [%s]\n",
                                strerror(errno));
                free(nlh);
                return rtn;
        }
        printf("nltpmd_init_netlink: Info - send netlink init msg to the kernel\n");

        // Recv the response from the kernel
        rtn = recvmsg(nltpmd_sock_fd, &msg, 0);
        if (rtn == -1)
        {
                printf("nltpmd_init_netlink: Error on recving netlink init msg from the kernel [%s]\n",
                                strerror(errno));
                free(nlh);
                return rtn;
        }

        // Retrive the data from the kernel
        printf("nltpmd_init_netlink: Info - got netlink init msg response from the kernel [%s] with pkt_len [%d]\n",
                        NLMSG_DATA(nlh), (NLMSG_DATA(nlh))->pkt_len);
        free(nlh);
        return 0;
}

static void usage(void)
{
	fprintf(stderr, "\tusage: nltpmd [-f] [-c <config file> [-h]\n\n");
	fprintf(stderr, "\t-f|--fake\tuse the fake TPM information (for testing)\n");
	fprintf(stderr, "\t-d|--debug\tenable debug mode\n");
	fprintf(stderr, "\t-c|--config\tpath to configuration file (TBD)\n");
	fprintf(stderr, "\t-h|--help\tdisplay this help message\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	int result;
	int newsd, c, option_index = 0;
	unsigned client_len;
	void *recv_buff;
	int recv_size;
	int send_size;
	struct hostent *client_hostent = NULL;
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"fake", 0, NULL, 'f'},
		{"debug", 0, NULL, 'd'},
		{"config", 1, NULL, 'c'},
		{0, 0, 0, 0}
	};

	/* Process the arguments */
	while ((c = getopt_long(argc, argv, "fhdc:", long_options, &option_index)) != -1) {
		switch (c) {
			case 'f':
				printf("nltpmd - Info: will use fake TPM info\n");
				use_fake_tpm_info = 1;
				break;
			case 'd':
				printf("nltpmd - Info: debug mode enabled\n");
				debug_enabled = 1;
				break;
			case 'c':
				printf("nltpmd - Warning: may support in future\n");
				break;
			case 'h':
				/* fall through */
			default:
				usage();
				return -1;
		}
	}

	/* Set the signal handlers */
	if (signals_init() != 0) {
		printf("nltpmd - Error: failed to set up the signal handlers\n");
		return -1;
	}

	/* Create the netlink socket */
	nltpmd_sock_fd = socket(PF_NETLINK, SOCK_RAW, NLTPMD_NETLINK);
	if (nltpmd_sock_fd < 0) {
		printf("nltpmd - Error: Failed netlink socket [%s]\n", strerror(errno));
		return -1;
	}

        /* Bind the socket */
	memset(&nltpmd_nl_addr, 0, sizeof(nltpmd_nl_addr));
	nltpmd_nl_addr.nl_family = AF_NETLINK;
        nltpmd_pid = getpid();
        printf("nltpmd - Info: pid [%lu]\n", nltpmd_pid);
        nltpmd_nl_addr.nl_pid = nltpmd_pid;
        if (bind(nltpmd_sock_fd, (struct sockaddr*)&nltpmd_nl_addr, sizeof(nltpmd_nl_addr)) == -1)
        {
                printf("nltpmd - Error: netlink bind failed [%s], aborting\n", strerror(errno));
                return -1;
        }

        /* Setup the netlink destination socket address */
        memset(&nltpmd_nl_dest_addr, 0, sizeof(nltpmd_nl_dest_addr));
        nltpmd_nl_dest_addr.nl_family = AF_NETLINK;
        nltpmd_nl_dest_addr.nl_pid = 0;
        nltpmd_nl_dest_addr.nl_groups = 0;
	printf("nltpmd - Info: nltpmd netlink socket init done\n");

	/* Prepare the recv buffer */
	recv_buff = calloc(1, NLTPMD_RECV_BUFF_LEN);

	/* Init the NLM stack */
	nlm_init_queue();

	/* Init the TPM worker - do the dirty job:) */
	result = tpmw_init_tpm(TPMW_MODE_TPMD);
	if (result != 0)
	{
		printf("nltpmd - Error: tpmw_init_tpm failed\n");
		return -1;
	}

	/* Send the initial testing nlmsgt to the kernel module */
	result = nltpmd_init_netlink();
	if (result != 0)
	{
		printf("nltpmd - Error: nltpmd_init_netlink failed\n");
		return -1;
	}
	
	printf("nltpmd - Info: nltpmd is up and running.\n");
	do {
		/* Recv the msg from the client */
		recv_size = recv(newsd, recv_buff, TPMD_RECV_BUFF_LEN, 0);
		if (recv_size == -1)
		{
			printf("tpmd - Error: recv failed [%s]\n", strerror(errno));
		}
		else if (recv_size == 0)
		{
			printf("tpmd - Warning: client socket is closed\n");
		}
		else if (recv_size % AT_REQ_LEN != 0)
		{
			printf("tpmd - Error: invalid AT msg size (may be garbage) - drop it\n");
		}
		else if (recv_size / AT_REQ_LEN != 1)
		{
			printf("tpmd - Info: got more than 1 AT msg - push the extras into AT queue\n");
			at_add_msg_queue((void *)(recv_buff+AT_REQ_LEN), (recv_size-AT_REQ_LEN), AT_MSG_REQ);
		}

		memcpy(&msg_req, recv_buff, AT_REQ_LEN);

		/* Handle the first msg and then go thru the queue */
		do
		{
			/* Debug */
			if (debug_enabled == 1)
				at_display_msg_req(&msg_req);

			/* Validate the msg */
			if (at_is_msg_req(&msg_req) != 1)
			{
				/* DDos may be considered here */
				printf("tpmd - Error: invalid AT request - drop it\n");
			}
			else
			{
				/* Process the AT request and generate the AT reply */
				if (tpmw_at_req_handler(&msg_rep, &msg_req, use_fake_tpm_info) != 0)
				{
					printf("tpmd - Error: tpmw_req_handler failed\n");
				}
				else
				{
					/* Debug */
					if (debug_enabled == 1)
						at_display_msg_rep(&msg_rep);

					/* Send the reply back */
					send_size = send(newsd, (void *)&msg_rep, AT_REP_LEN, 0);
					if (send_size != AT_REP_LEN)
						printf("tpmd - Error: send failed [%s]\n", strerror(errno));
					else
						printf("tpmd - Info: sent an reply to host [%s]\n", hostname);
				}
			}

		} while ((at_get_msg_num_queue(AT_MSG_REQ) != 0) && (at_pop_head_msg_queue(&msg_req, AT_MSG_REQ) == 0));

	} while (1);

	/* To close correctly, we must receive a SIGTERM */
	return 0;
}

