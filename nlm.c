/*
 * Source file for protocol AT
 * Detailed design of AT please refer to the web
 * Sep 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nlm.h"

/* AT queue definitions */
static unsigned char *at_req_queue;
static unsigned char *at_req_queue_ptr;	/* Always pointing to the next avalible position */
static unsigned char *at_rep_queue;
static unsigned char *at_rep_queue_ptr;	/* The same here */

/* AT protocol related methods */

/* Check if this msg is a valid AT request */
int at_is_msg_req(void *msg)
{
	at_req *req = (char *)msg;
	if (req->header[0] == 'a' && req->header[1] == 't' && req->header[2] == 'q')
		return 1;
	return 0;
}

/* Check if this msg is a valid  AT reply */
int at_is_msg_rep(void *msg)
{
	at_rep *rep = (char *)msg;
	if (rep->header[0] == 'a' && rep->header[1] == 't' && rep->header[2] == 'p')
		return 1;
	return 0;
}

/* Display the uchar given length */
void at_display_uchar(unsigned char *src, int len, char *header)
{
	int i;
	printf("%s\n", header);
	for (i = 0; i < len; i++)
	{
		if ((i+1) % AT_UCHAR_NUM_PER_LINE != 0)
			printf("%02x ", src[i]);
		else
			printf("%02x\n", src[i]);
	}
	printf("\n");	
}

/* Display the PCR list */
void at_display_pcr_list(unsigned char *pcr)
{
	int i;
	printf("PCR list:\n");
	for (i = 0; i < AT_PCR_LIST_LEN; i++)
	{
		printf("%d", pcr[i]);
	}
	printf("\n");
}

/* Display the AT request */
void at_display_msg_req(at_req *req)
{
	printf("AT request:\n"
		"Header:\n[%c %c %c]\n",
		req->header[0],
		req->header[1],
		req->header[2]);
	at_display_pcr_list(req->pcr_list);
	at_display_uchar(req->nonce, AT_NONCE_LEN, "Nonce:");
}

/* Display the AT reply */
void at_display_msg_rep(at_rep *rep)
{
	printf("AT reply:\n"
		"Header:\n[%c %c %c]\n",
		rep->header[0],
		rep->header[1],
		rep->header[2]);
	at_display_uchar(rep->data, AT_DATA_LEN, "Data:");
	at_display_uchar(((at_data *)(rep->data))->header, AT_DATA_HEADER_LEN, "Data header:");
	at_display_uchar(((at_data *)(rep->data))->digest, AT_PCR_DIGEST_LEN, "Data digest:");
	at_display_uchar(((at_data *)(rep->data))->nonce, AT_NONCE_LEN, "Data nonce:");
	at_display_uchar(rep->sig, AT_SIG_LEN, "Signature:");
}


/* AT queue related methods */

/* Init the AT queue */
void at_init_queue(int type)
{
	if (type == AT_MSG_REQ)
	{
		/* Init the AT request queue */
		at_req_queue = (unsigned char *)malloc(AT_QUEUE_REQ_SIZE);
		at_req_queue_ptr = at_req_queue;
	}
	else if (type == AT_MSG_REP)
	{
		/* Init the AT reply queue */
		at_rep_queue = (unsigned char *)malloc(AT_QUEUE_REP_SIZE);
		at_rep_queue_ptr = at_rep_queue;
	}
	else
	{
		printf("AT - Error: unknown queue type [%d]\n", type);
	}
}

/* Add msgs into the AT queue */
void at_add_msg_queue(void *msg, int len, int type)
{
	int num_of_msg_in_queue;
	int num_of_msg_requested;
	int num_of_msg_to_be_pushed;

	/* Defensive checking */
	if (len == 0)
		return;

	if (type == AT_MSG_REQ)
	{
		/* Get the queue status */
		num_of_msg_in_queue = at_get_msg_num_queue(type);
		num_of_msg_requested = len % AT_REQ_LEN;
		num_of_msg_to_be_pushed = num_of_msg_requested;
		if (num_of_msg_in_queue + num_of_msg_requested > AT_QUEUE_MSG_NUM)
		{
			num_of_msg_to_be_pushed = AT_QUEUE_MSG_NUM - num_of_msg_in_queue;
			printf("AT - Warning: not enough space to hold all the msgs\n"
				"num_of_msg_in_queue [%d], num_of_msg_requested [%d], "
				"num_of_msg_to_be_pushed [%d], num_of_msg_to_be_dropped [%d]\n",
				num_of_msg_in_queue,
				num_of_msg_requested,
				num_of_msg_to_be_pushed,
				(num_of_msg_requested - num_of_msg_to_be_pushed));
		}

		/* Push the msg into the queue */
		if (num_of_msg_to_be_pushed != 0)
		{
			memcpy(at_req_queue_ptr, msg, (num_of_msg_to_be_pushed*AT_REQ_LEN));
			at_req_queue_ptr += num_of_msg_to_be_pushed * AT_REQ_LEN;
		}
	}
	else if (type == AT_MSG_REP)
	{
                /* Get the queue status */
                num_of_msg_in_queue = at_get_msg_num_queue(type);
                num_of_msg_requested = len % AT_REP_LEN;
                num_of_msg_to_be_pushed = num_of_msg_requested;
                if (num_of_msg_in_queue + num_of_msg_requested > AT_QUEUE_MSG_NUM)
                {   
                        num_of_msg_to_be_pushed = AT_QUEUE_MSG_NUM - num_of_msg_in_queue;
                        printf("AT - Warning: not enough space to hold all the msgs\n"
                                "num_of_msg_in_queue [%d], num_of_msg_requested [%d], "
                                "num_of_msg_to_be_pushed [%d], num_of_msg_to_be_dropped [%d]\n",
                                num_of_msg_in_queue,
                                num_of_msg_requested,
                                num_of_msg_to_be_pushed,
                                (num_of_msg_requested - num_of_msg_to_be_pushed));
                }   

                /* Push the msg into the queue */
                if (num_of_msg_to_be_pushed != 0)
                {   
                        memcpy(at_rep_queue_ptr, msg, (num_of_msg_to_be_pushed*AT_REP_LEN));
                        at_rep_queue_ptr += num_of_msg_to_be_pushed * AT_REP_LEN;
                }   
	}
	else
	{
		printf("AT - Error: unknown queue type [%d]\n", type);
	}
}

/* Pop the first msg in the queue */
int at_pop_head_msg_queue(void *msg, int type)
{
	/* NOTE: user's responsibility to make sure *msg has enough mem */
	int num;

	if (type == AT_MSG_REQ)
	{
		/* Make sure we have at least one msg */
		num = at_get_msg_num_queue(type);
		if (num == 0)
		{
			printf("AT - Warning: no msg available in the AT request queue\n");
			/* Make the buff to be null */
			memset(msg, 0, AT_REQ_LEN);
			return -1;
		}

		/* Pop up the first msg in the queue */
		memcpy(msg, (void *)at_req_queue, AT_REQ_LEN);
		memmove(at_req_queue,
			(at_req_queue + AT_REQ_LEN),
			(size_t)(at_req_queue_ptr - at_req_queue - AT_REQ_LEN));
		at_req_queue_ptr -= AT_REQ_LEN;
	}
	else if (type == AT_MSG_REP)
	{
                /* Make sure we have at least one msg */
                num = at_get_msg_num_queue(type);
                if (num == 0)
                {
                        printf("AT - Warning: no msg available in the AT reply ueue\n");
                        /* Make the buff to be null */
                        memset(msg, 0, AT_REP_LEN);
                        return -1;
                }

                /* Pop up the first msg in the queue */
                memcpy(msg, (void *)at_rep_queue, AT_REP_LEN);
                memmove(at_rep_queue,
                        (at_rep_queue + AT_REP_LEN),
                        (size_t)(at_rep_queue_ptr - at_rep_queue - AT_REP_LEN));
                at_rep_queue_ptr -= AT_REP_LEN;
	}
	else
	{
		printf("AT - Error: unknown queue type [%d]\n", type);
		return -1;
	}

	return 0;
}

/* Get the number of msgs in the queue */
int at_get_msg_num_queue(int type)
{
	if (type == AT_MSG_REQ)
		return (at_req_queue_ptr - at_req_queue)/AT_REQ_LEN;
	else if (type == AT_MSG_REP)
		return (at_rep_queue_ptr - at_rep_queue)/AT_REP_LEN;
	else
		printf("AT - Error: unknown queue type [%d]\n", type);

	return -1;	
}

/* Clear all the msgs in the queue */
void at_clear_all_msg_queue(int type)
{
	if (type == AT_MSG_REQ)
		at_req_queue_ptr = at_req_queue;
	else if (type = AT_MSG_REP)
		at_rep_queue_ptr = at_rep_queue;
	else
		printf("AT - Error: unknown queue type [%d]\n", type);
}


