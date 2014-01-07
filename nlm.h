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
typedef struct _nlmsgk
{
	int pkt_len;
	unsigned char *pkt;
} nlmsgk;

typedef struct _nlmsgt
{
	unsigned char sig[NLM_SIG_LEN];
	int pkt_len;
	unsigned char *pkt;
} nlmsgt;

#define NLM_MSGK_LEN		sizeof(nlmsgk)
#define NLM_MSGT_LEN		sizeof(nlmsgt)
#define NLM_QUEUE_MSG_NUM	100
#define NLM_QUEUE_SIZE		(NLM_MSGK_LEN*NLM_QUEUE_MSG_NUM)

/* NLM protocol related methods */

/* Check if this msg is a valid nlmsgk msg */
int nlm_is_msg_nlmsgk(void *msg);

/* Display the nlmsgk msg */
void nlm_display_msg_nlmsgk(nlmsgk *msg);

/* Display the nlmsgt msg */
void nlm_display_msg_nlmsgt(nlmsgt *msg);

/* Display the uchar given length */
void nlm_display_uchar(unsigned char *src, int len, char *header);

/* Display the PCR list */
//void at_display_pcr_list(unsigned char *pcr);


/* AT queue related methods */

/* Init the NLM queue */
void at_init_queue(void);

/* Add msgs into the NLM queue */
void nlm_add_msg_queue(nlmsgk *msg);

/* Pop the first msg in the queue */
int nlm_pop_head_msg_queue(nlmsgk *msg);

/* Get the number of msgs in the queue */
int nlm_get_msg_num_queue(void);

/* Clear all the msgs in the queue */
void nlm_clear_all_msg_queue(void);

#endif
