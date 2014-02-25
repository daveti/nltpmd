/*
 * Source file for protocol NLM
 * Used by the nltpmd to save the raw packet from the kernel
 * Jan 8, 2014
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nlm.h"

/* NLM queue definitions */
static nlmsgt nlm_queue[NLM_QUEUE_MSG_NUM];
static int nlm_queue_index;	/* Always pointing to the next avalible position */

/* NLM protocol related methods */

/* Display the uchar given length */
void nlm_display_uchar(unsigned char *src, int len, char *header)
{
	int i;
	printf("%s\n", header);
	for (i = 0; i < len; i++)
	{
		if ((i+1) % NLM_UCHAR_NUM_PER_LINE != 0)
			printf("%02x ", src[i]);
		else
			printf("%02x\n", src[i]);
	}
	printf("\n");	
}

/* Display the NLM message */
void nlm_display_msg(nlmsgt *msg)
{
	nlm_display_uchar(msg->sig, NLM_SIG_LEN, "Signature:");
	printf("Packet Len: [%d]\n", msg->pkt_len);
	nlm_display_uchar(msg->pkt, msg->pkt_len, "Packet:");
}


/* NLM queue related methods */

/* Init the NLM queue */
void nlm_init_queue(void)
{
	memset((unsigned char *)nlm_queue, 0, NLM_QUEUE_SIZE);
	nlm_queue_index = 0;
}

/* Add raw msgs into the NLM queue */
int nlm_add_raw_msg_queue(unsigned char *src, int len)
{
	int parsed_index = 0;
	int pkt_len;
	nlmsgt msg;
	unsigned char *pkt;

	/* Initial defensive checking */
	if (len == 0)
		return 0;

	if (len < 4)
	{
		printf("nlm_add_raw_msg_queue: Error - incomplete TLV data with len [%d]\n", len);
		return -1;
	}

	/* Convert the raw TLV data into nlmsgt */
	while (parsed_index < len)
	{
		/* Convert the first 4 bytes into int length */
		if (parsed_index + 4 >= len)
		{
			printf("nlm_add_raw_msg_queue: Error - incomplete TLV data (broken pkt_len) with parsed len [%d] and total len [%d]\n",
				parsed_index, len);
			return -1;
		}
		memcpy(&pkt_len, (src+parsed_index), 4);
		parsed_index += 4;

		/* Defensive checking for pkt_len */
		if (pkt_len == 0)
		{
			printf("nlm_add_raw_msg_queue: Error - got zero length pkt with parsed len [%d] and total len [%d]\n",
				parsed_index, len);
			return -1;
		}

		/* Hunt for the IP pkt data */
		/* NOTE: parsed_index + pkt_len could == len */
		if (parsed_index + pkt_len > len)
		{
			printf("nlm_add_raw_msg_queue: Error - incomplete TLV data (broken pkt) with parsed len [%d] and total len [%d]\n",
				parsed_index, len);
			return -1;
		}
		pkt = (unsigned char *)malloc(pkt_len);
		memcpy(pkt, (src+parsed_index), pkt_len);
		parsed_index += pkt_len;

		/* Save the TLV into nlm msg queue */
		if (nlm_queue_index < NLM_QUEUE_MSG_NUM)
		{
			memset(&msg, 0, sizeof(msg));
			msg.pkt_len = pkt_len;
			msg.pkt = pkt;
			nlm_queue[nlm_queue_index] = msg;
			nlm_queue_index++;
		}
		else
		{
			printf("nlm_add_raw_msg_queue: Error - nlm queue is full\n");
			free(pkt);
			return -1;
		}
	}

	return 0;
}

/* Clear all the msgs in the queue */
void nlm_clear_all_msg_queue(void)
{
	int i;

	/* Free the internal memory of each msg */
	for (i = 0; i < nlm_queue_index; i++)
		free(nlm_queue[i].pkt);

	/* Reinit the index */
	nlm_queue_index = 0;
}

/* Get the number of msgs in the queue */
int nlm_get_msg_num_queue(void)
{
	return nlm_queue_index;
}

/* Get the msg from the queue based on the index */
nlmsgt * nlm_get_msg_queue(int index)
{
	return &(nlm_queue[index]);
}

