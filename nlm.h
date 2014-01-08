/*
 * Header file for netlink messaging
 * Dec 12, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef NLM_INCLUDE
#define NLM_INCLUDE

/* NLM macros */
#define NLM_SIG_LEN		256
#define NLM_DIGEST_LEN		20

/* Definition for the netlink msgs */
typedef struct _nlmsgt
{
	unsigned char sig[NLM_SIG_LEN];
	int pkt_len;
	unsigned char *pkt;
} nlmsgt;

#define NLM_MSG_LEN		sizeof(nlmsgt)
#define NLM_QUEUE_MSG_NUM	1000
#define NLM_QUEUE_SIZE		(NLM_MSG_LEN*NLM_QUEUE_MSG_NUM)

/* NLM protocol related methods */

/* Display the nlmsgt msg */
void nlm_display_msg(nlmsgt *msg);

/* Display the uchar given length */
void nlm_display_uchar(unsigned char *src, int len, char *header);



/* NLM queue related methods */

/* Init the NLM queue */
void nlm_init_queue(void);

/* Add a msg into the NLM queue */
void nlm_add_msg_queue(nlmsgt *msg);

/* Add msgs into the NLM queue from raw binary data */
int nlm_add_raw_msg_queue(unsigned char *src, int len);

/* Pop the first msg in the queue */
void nlm_pop_head_msg_queue(void);

/* Get the number of msgs in the queue */
int nlm_get_msg_num_queue(void);

/* Check if the queue is full */
int nlm_is_full_queue(void);

/* Clear all the msgs in the queue */
void nlm_clear_all_msg_queue(void);

#endif
