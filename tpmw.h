/*
 * tpmw.h
 * Header file for tpmw
 * Feb 23, 2014
 * Add support for nltpmd and comment AT protocol related
 * daveti
 * Sep 16, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef TPMW_INCLUDE
#define TPMW_INCLUDE

#include <trousers/tss.h>
#include <trousers/trousers.h>
#include "nlm.h"

/* TPM local definitions
NOTE: this should be configurable in future.
But now, just let it be:)
NOTE: the SRK passwd are shared between arpsecd and tpmd.
Have to make 2 builds if the passwds are different...
(I know, it sounds stupid. But - K.I.S.S.)
*/
#define TPMW_SRK_PASSWD			"00000000000000000000"
#define TPMW_TSS_UUID_AIK		{0, 0, 0, 0, 0, {0, 0, 0, 0, 2, 0}}
#define TPMW_PCR_NUM_MAX		24
#define TPMW_PCR_BYTE			2
#define TPMW_PCR_LEN			20
#define TPMW_NONCE_LEN			20
#define TPMW_PCR_DIGEST_LEN		20
#define TPMW_MODE_ARPSECD		0
#define TPMW_MODE_TPMD			1
#define TPMW_MODE_NLTPMD		2
#define TPMW_NUM_PER_LINE		20

/* Interface with tpmd and arpsecd */

/* Init the tpmw with TPM */
int tpmw_init_tpm(int mode);

/* Close the TPM */
void tpmw_close_tpm(void);

/* Clear the global records */
void tpmw_clear_global_records(void);

#ifndef TPMW_MODE_NLTPMD
/* Main method to process AT request */
int tpmw_at_req_handler(at_rep *rep, at_req *req, int fake);

/* Main method to process AT reply */
int tpmw_at_rep_handler(at_rep *rep);
#endif


/* TPM local methods - talking with tcsd */

/* General methods */

/* SHA1 */
int tpmw_sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest);

/* Display the PCRs */
void tpmw_display_pcrs();

/* Display the TSS validation structure */
void tpmw_display_validation(TSS_VALIDATION *valid);

/* Display the uchar with better format */
void tpmw_display_uchar(unsigned char *src, int len, char *header);

/* Generate the nonce locally */
int tpmw_generate_nonce(unsigned char *nonce);

/* Get the PCR value based on the PCR mask */
int tpmw_get_pcr_value(void);


/* For tpmd */

#ifndef TPMW_MODE_NLTPMD
/* Generate the fake AT reply - for UT */
void tpmw_generate_fake_at_rep(at_rep *rep);
#endif

/* Get the quote using AIK */
TSS_VALIDATION *tpmw_get_quote_with_aik(void);

#ifndef TPMW_MODE_NLTPMD
/* Generate the AT reply based on validation struct */
void tpmw_generate_at_rep(at_rep *rep, TSS_VALIDATION *valid);
#endif


/* For arpsecd */

/* Load the TPM DB entry into tpmw */
void tpmw_load_db_entry(unsigned char *pcr_mask, unsigned char *pcr_value, int pcr_value_len, unsigned char *key, int key_len);

#ifndef TPMW_MODE_NLTPMD
/* Generate the AT request */
int tpmw_generate_at_req(at_req *req);
#endif

/* Init the PCR hash buf for future PCR digest verification */
void tpmw_init_pcr_hash_buf(void);

/* Generate the complete PCR hash buf based on PCR mask and value */
void tpmw_generate_pcr_hash_buf(unsigned char *pcr_value, int len);

#ifndef TPMW_MODE_NLTPMD
/* Verify the signature by loading AIK pub key and computing hash */
int tpmw_verify_signature(unsigned char *data, unsigned char *sig);
#endif


/* For nltpmd */

/* Sign the packet */
int tpmw_sign_packet(nlmsgt *ptr);


#endif
