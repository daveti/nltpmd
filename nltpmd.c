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
#define NLTPMD_NETLINK		31
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
static int nltpmd_init_netlink(void)
{
        struct nlmsghdr *nlh;
        struct iovec iov;
        struct msghdr msg;
        int rtn;
	char *init_msg = "hello_from_nltpmd";
	int init_msg_len = strlen(init_msg) + 1;
	int len;

        // Init the stack struct to avoid potential error
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));

        // Create the netlink msg
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(init_msg_len));
        memset(nlh, 0, NLMSG_SPACE(init_msg_len));
        nlh->nlmsg_len = NLMSG_SPACE(init_msg_len);
        nlh->nlmsg_pid = nltpmd_pid;
        nlh->nlmsg_flags = 0;

	// Add the hello string into the msg
	memcpy(NLMSG_DATA(nlh), init_msg, init_msg_len);

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
        memcpy(&len, NLMSG_DATA(nlh), 4);
        printf("nltpmd_init_netlink: Info - got netlink init msg response from the kernel [%s] len [%d]\n",
                        (char *)(NLMSG_DATA(nlh)+4), len);
        free(nlh);
        return 0;
}

/* Send the nlmsgt via the netlink socket */
static int nltpmd_netlink_send(nlmsgt *msg_ptr)
{
        struct nlmsghdr *nlh;
        struct iovec iov;
        struct msghdr msg;
        int rtn;
	unsigned char *data;
	int data_len;

	// Convert the nlmsgt into binary data
	data_len = NLM_SIG_LEN + 4 + msg_ptr->pkt_len;
	data = (unsigned char *)malloc(data_len);
	memcpy(data, msg_ptr->sig, NLM_SIG_LEN);
	memcpy((data+NLM_SIG_LEN), &(msg_ptr->pkt_len), 4);
	memcpy((data+NLM_SIG_LEN+4), msg_ptr->pkt, msg_ptr->pkt_len);

        // Init the stack struct to avoid potential error
        memset(&iov, 0, sizeof(iov));
        memset(&msg, 0, sizeof(msg));

        // Create the netlink msg
        nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(data_len));
        memset(nlh, 0, NLMSG_SPACE(data_len));
        nlh->nlmsg_len = NLMSG_SPACE(data_len);
        nlh->nlmsg_pid = nltpmd_pid;
        nlh->nlmsg_flags = 0;

        // Copy the binary data into the netlink message
	memcpy(NLMSG_DATA(nlh), data, data_len);
	if (debug_enabled == 1)
		nlm_display_uchar(NLMSG_DATA(nlh), data_len, "netlink data:");

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
                printf("nltpmd_netlink_send: Error on sending netlink msg to the kernel [%s]\n",
                                strerror(errno));
                free(nlh);
		free(data);
                return rtn;
        }

        printf("nltpmd_netlink_send: Info - send netlink msg to the kernel\n");
        free(nlh);
	free(data);
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
	int c, option_index = 0;
	void *recv_buff;
	int recv_size;
	int num_of_msg;
	int i;
	nlmsgt *msg_ptr;
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
        printf("nltpmd - Info: pid [%u]\n", nltpmd_pid);
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
	struct iovec iov = { recv_buff, NLTPMD_RECV_BUFF_LEN };
	struct nlmsghdr *nh;
	struct nlmsgerr *nlm_err_ptr;
	struct msghdr msg = { &nltpmd_nl_dest_addr,
		sizeof(nltpmd_nl_dest_addr),
		&iov, 1, NULL, 0, 0 };

	/* Init the NLM queue */
	nlm_init_queue();

	/* Init the TPM worker - do the dirty job:) */
	result = tpmw_init_tpm(TPMW_MODE_NLTPMD);
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

	/* Test the TPM hashing function */
	/* TODO */

	printf("nltpmd - Info: nltpmd is up and running.\n");

	do {
		/* Recv the msg from the kernel */
		recv_size = recvmsg(nltpmd_sock_fd, &msg, 0);
		if (recv_size == -1) {
			printf("nltpmd - Error: recv failed [%s]\n", strerror(errno));
			continue;
		}
		else if (recv_size == 0) {
			printf("nltpmd - Warning: kernel netlink socket is closed\n");
			continue;
		}

		/* Pop nlmsgs into the NLM queue
		 * Note that we do not allow multipart msg from the kernel.
		 * So we do not have to call NLMSG_NEXT() and only one msg
		 * would be recv'd for each recvmsg call. NLM queue seems
		 * to be redundant if nltpmd is single thread. But it is
		 * needed if TPM pkt signing is the other thread.
		 * Feb 24, 2014
		 * daveti
		 */
		nh = (struct nlmsghdr *)recv_buff;
		if (NLMSG_OK(nh, recv_size))
		{
			/* Make sure the msg is alright */
			if (nh->nlmsg_type == NLMSG_ERROR)
			{
				nlm_err_ptr = (struct nlmsgerr *)(NLMSG_DATA(nh));
				printf("nltpmd - Error: nlmsg error [%d]\n",
					nlm_err_ptr->error);
				continue;
			}

			/* Ignore the noop */
			if (nh->nlmsg_type == NLMSG_NOOP)
				continue;

			/* Defensive checking - should always be non-multipart msg */
			if (nh->nlmsg_type != NLMSG_DONE)
			{
				printf("nltpmd - Error: nlmsg type [%d] is not supported\n",
					nh->nlmsg_type);
				continue;
			}

			/* Pop the msg into the NLM queue */
			if (nlm_add_raw_msg_queue(NLMSG_DATA(nh),
					NLMSG_PAYLOAD(nh, recv_size)) != 0)
			{
				printf("nltpmd - Error: nlm_add_raw_msg_queue failed\n");
				continue;
			}
		}
		else
		{
			printf("nltpmd - Error: netlink msg is corrupted\n");
			continue;
		}

		/* NOTE: even if nlm_add_raw_msg_queue may fail, there may be msgs in queue
		 * Right now, nltpmd is single thread - recving msgs from the kernel space
		 * and then processing each msg upon this recving. However, the code below
		 * could be separated into a worker thread which could run parallelly with
		 * the main thread. This may be an option to improve the performance even
		 * the mutex has to be added into NLM queue implementation...
		 * Feb 24, 2014
		 * daveti
		 */

		/* Go thru the queue */
		num_of_msg = nlm_get_msg_num_queue(); /* should be always 1 */
		if (debug_enabled == 1)
			printf("nltpmd - Debug: got [%d] msgs(packets) in the queue\n", num_of_msg);

		for (i = 0; i < num_of_msg; i++)
		{
			/* Get the nlmsgt msg */
			msg_ptr = nlm_get_msg_queue(i);

			/* Debug */
			if (debug_enabled == 1)
				nlm_display_msg(msg_ptr);

			/* Get the signature of the packet */
			result = tpmw_sign_packet(msg_ptr);
			if (result != 0)
				printf("nltpmd - Error: tpmw_sign_packet failed\n");
			else
			{
				/* Send the nlmsgt to the kernel */
				if (debug_enabled == 1)
					nlm_display_msg(msg_ptr);

				result = nltpmd_netlink_send(msg_ptr);
				if (result != 0)
					printf("nltpmd - Error: nltpmd_netlink_send failed\n");
			}
		}

		/* Clear the queue before recving again */
		nlm_clear_all_msg_queue();

	} while (1);

	/* To close correctly, we must receive a SIGTERM */
	return 0;
}

