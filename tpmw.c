/*
 * tpmw.c
 * Source file for tpmw
 * TPM worker (tpmw) is used to pass the AT request/reply
 * to the local TPM (tcsd) and generate the corresponding
 * AT reply or msg validation.
 * NOTE: NOT thread-safe!
 * Sep 16, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include "tpmw.h"

/* Global definition for TPM info and resource */
static unsigned char tpmw_nonce[TPMW_NONCE_LEN];
static unsigned char tpmw_pcr_mask[TPMW_PCR_NUM_MAX];
static unsigned char tpmw_pcr_value[TPMW_PCR_NUM_MAX][TPMW_PCR_LEN];

/* To accelerate the speed of talking to TPM
 * Only 1 context will be created and will be kept
 * alive while tpmd/arpsecd is running.
 * -daveti
 */
static int				debug_enabled = 1;
static TSS_HCONTEXT			hContext;
static TSS_HTPM				hTPM;
static TSS_HKEY				hIdentKey;	// AIK used by tpmd
static TSS_HKEY				hKey;		// Sign key used by arpsecd
static unsigned char			*tpmw_pcr_hash_buf;
static int				tpmw_pcr_hash_len;
static unsigned char			*tpmw_aik_pub_key;
static int				tpmw_aik_pub_key_len;

/* Interface with tpmd and arpsecd */

/* Init the tpmw with TPM */
int tpmw_init_tpm(int mode)
{
        TSS_HKEY        hSRK;
        TSS_RESULT      result;
        TSS_UUID        SRK_UUID = TSS_UUID_SRK;
	TSS_UUID        AIK_UUID = TPMW_TSS_UUID_AIK;
        TSS_HPOLICY     hSrkPolicy;
        UINT32          pulPubKeyLength;
        BYTE            *prgbPubKey;

	/* Trousers preamble */
        result = Tspi_Context_Create(&hContext);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_Create failed [%s]\n",
			Trspi_Error_String(result));
		return -1;
        }

        result = Tspi_Context_Connect(hContext, NULL);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_Connect failed [%s]\n",
			Trspi_Error_String(result));
		goto close;
        }

        result = Tspi_Context_GetTpmObject (hContext, &hTPM);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_GetTpmObject failed [%s]\n",
			Trspi_Error_String(result));
		goto close;
        }

        result = Tspi_Context_LoadKeyByUUID(hContext,
                        TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_LoadKeyByUUID for SRK failed [%s]\n",
			Trspi_Error_String(result));
		goto close;
        }

        result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_GetPolicyObject for SRK failed [%s]\n",
			Trspi_Error_String(result));
		goto close;
        }

        result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN, 20, TPMW_SRK_PASSWD);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Policy_SetSecret for SRK failed [%s]\n",
			Trspi_Error_String(result));
		goto close;
        }

	/* Load the AIK into the context if this is for tpmd */
	if (mode == TPMW_MODE_TPMD)
	{
		result = Tspi_Context_LoadKeyByUUID(hContext,
				TSS_PS_TYPE_SYSTEM, AIK_UUID, &hIdentKey);
		if (result != TSS_SUCCESS) {
			printf ("Tspi_Context_LoadKeyByUUID for AIK failed [%s]\n",
				Trspi_Error_String(result));
			goto close;
		}

		/* Get the pub key for debugging */
		if (debug_enabled == 1)
		{
			result = Tspi_Key_GetPubKey(hIdentKey, &pulPubKeyLength, &prgbPubKey);
			if (result != TSS_SUCCESS)
			{
				printf("Tspi_Key_GetPubKey failed [%s]\n",
					Trspi_Error_String(result));
				goto close;
			}

        		/* Output the pub key of AIK */
        		tpmw_display_uchar(prgbPubKey, pulPubKeyLength, "tpmw - AIK pub key:");
		}
        }

	/* Prepare the global buf for PCR hashing
	 * NOTE: the header of the PCR hashing is a little bit tricky.
	 * Actually, it should be calculated using TPM_GetCapability.
	 * However, tpmw will use hard code here to avoid extra info from
	 * the remote machine as we are using the same TPM hardwares.
	 * But in case things go crazy, check the code of tqt
	 * http://github.com/daveti/tqt
	 * Sep 19, 2013
	 * -daveti
	 */
	if (mode == TPMW_MODE_ARPSECD)
	{
		tpmw_init_pcr_hash_buf();
	}

	return 0;
close:
	tpmw_close_tpm();
	return -1;
}

/* Close the TPM */
void tpmw_close_tpm(void)
{
	if (tpmw_pcr_hash_buf != NULL) 
		free(tpmw_pcr_hash_buf);
	if (tpmw_aik_pub_key != NULL)
		free(tpmw_aik_pub_key);
	Tspi_Context_Close(hContext);
}

/* Clear the global records */
void tpmw_clear_global_records(void)
{
	int i;

	memset(tpmw_nonce, 0, TPMW_NONCE_LEN);
	memset(tpmw_pcr_mask, 0, TPMW_PCR_NUM_MAX);
	for (i = 0; i < TPMW_PCR_NUM_MAX; i++)
	{
		memset(tpmw_pcr_value[i], 0, TPMW_PCR_LEN);
	}
}

/* Main method to process AT request  - tpmd */
int tpmw_at_req_handler(at_rep *rep, at_req *req, int fake)
{
	TSS_VALIDATION *valid;
	TPM_QUOTE_INFO *quote;

	/* Check if this is UT */
	if (fake == 1)
	{
		printf("tpmw - AT reply will be faked\n");
		tpmw_generate_fake_at_rep(rep);
		return 0;
	}

	/* Clear the global records */
	tpmw_clear_global_records();

	/* Get the PCR mask from the AT request */
	memcpy(tpmw_pcr_mask, req->pcr_list, TPMW_PCR_NUM_MAX);

	/* Display the PCR mask for debug */
	if (debug_enabled == 1)
		tpmw_display_uchar(tpmw_pcr_mask, TPMW_PCR_NUM_MAX, "tpmw - got PCR mask:");

	/* Get the nonce from the AT request */
	memcpy(tpmw_nonce, req->nonce, TPMW_NONCE_LEN);

	/* Display the nonce for debug */
	if (debug_enabled == 1)
		tpmw_display_uchar(tpmw_nonce, TPMW_NONCE_LEN, "tpmw - got nonce:");

	/* Display the PCR value for debug */
	if (debug_enabled == 1)
		if (tpmw_get_pcr_value() == 0)
			tpmw_display_pcrs();

	/* Get the quote using AIK */
	valid = tpmw_get_quote_with_aik();
	if (valid == NULL)
	{
		printf("tpmw - Error on tpmw_get_quote_with_aik\n");
		return -1;
	}

	/* Display the validation structure for debug */
	if (debug_enabled == 1)
	{
	        /* Get the digest of PCRs value */
		quote = (TPM_QUOTE_INFO *)valid->rgbData;
		tpmw_display_uchar(quote->compositeHash.digest, TPMW_NONCE_LEN, "PCRs value digest:");
		tpmw_display_validation(valid);

		/* Verify the digest locally */
		/* This may be needed - daveti */
	}

	/* Write the AT reply back */
	tpmw_generate_at_rep(rep, valid);

	/* Free the valid struct */
	free(valid);

	return 0;
}

/* Main method to process AT reply  - arpsecd */
/* Return 0 - if PCR hash digest and signature both pass the verification */
/* Return -1 - otherwise */
int tpmw_at_rep_handler(at_rep *rep)
{
	unsigned char digest[TPMW_PCR_DIGEST_LEN];

	/* Retrieve the nonce for antiRelay checking */
	if (memcmp(((at_data *)(rep->data))->nonce, tpmw_nonce, TPMW_NONCE_LEN) != 0)
	{
		printf("tpmw - Warning: got an unknown AT reply with different nonce\n");
		if (debug_enabled == 1)
			at_display_msg_rep(rep);
		return -1;
	}

	/* Compute the PCR digest locally */
	if (tpmw_sha1(hContext, tpmw_pcr_hash_buf, tpmw_pcr_hash_len, digest) != 0)
	{
		printf("tpmw - Error on tpmw_sha1\n");
		return -1;
	}

	/* Verify the PCR digest */
	if (memcmp(((at_data *)(rep->data))->digest, digest, TPMW_PCR_DIGEST_LEN) != 0)
	{
		printf("tpmw - Error: PCR digest verification failure\n");
		if (debug_enabled == 1)
		{
			tpmw_display_uchar(((at_data *)(rep->data))->digest, TPMW_PCR_DIGEST_LEN, "Remote PCR digest:");
			tpmw_display_uchar(digest, TPMW_PCR_DIGEST_LEN, "Local PCR digest:");
		}
		return -1;
	}

	/* Verify the signature */
	if (tpmw_verify_signature(rep->data, rep->sig) != 0)
	{
		printf("tpmw - Error: Signature verification failure\n");
		if (debug_enabled == 1)
			tpmw_display_uchar(rep->sig, AT_SIG_LEN, "Remote signature:");
		return -1;
	}

	return 0;
}


/* TPM local methods - talking with tcsd */

/* General methods */

/* SHA1 */
int tpmw_sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest)
{
	TSS_RESULT	result;
        TSS_HHASH       hHash;
        BYTE            *tmpbuf;
        UINT32          tmpbufLen;
	int		rtn;

        result = Tspi_Context_CreateObject(hContext,
                                TSS_OBJECT_TYPE_HASH,
                                TSS_HASH_SHA1,
                                &hHash);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Context_CreateObject failed for hash object [%s]\n",
			Trspi_Error_String(result));
		return -1;
	}

        result = Tspi_Hash_UpdateHashValue(hHash, bufLen, (BYTE *)buf);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Hash_UpdateHashValue failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

        result = Tspi_Hash_GetHashValue(hHash, &tmpbufLen, &tmpbuf);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Hash_GetHashValue failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

        memcpy(digest, tmpbuf, tmpbufLen);
	rtn = 0;
close:
        Tspi_Context_FreeMemory(hContext, tmpbuf);
        Tspi_Context_CloseObject(hContext, hHash);
	return rtn;
}

/* Display the PCRs */
void tpmw_display_pcrs()
{
	int i;

        printf("tpmw - PCRs:\n");
        for(i = 0; i < TPMW_PCR_NUM_MAX; i++)
        {
		if (tpmw_pcr_mask[i] == 1)
		{
                	printf("PCR-%02d: ", i);
			tpmw_display_uchar(tpmw_pcr_value[i], TPMW_PCR_LEN, NULL);
		}
        }
}

/* Display the TSS validation structure */
void tpmw_display_validation(TSS_VALIDATION *valid)
{
        printf("Validation struct:\n");
        printf("ulExternalDataLength = %u\n", valid->ulExternalDataLength);
        tpmw_display_uchar(valid->rgbExternalData, valid->ulExternalDataLength, "ExternalData:");
        printf("ulDataLength = %u\n", valid->ulDataLength);
        tpmw_display_uchar(valid->rgbData, valid->ulDataLength, "Data:");
        printf("ulValidationDataLength = %u\n", valid->ulValidationDataLength);
        tpmw_display_uchar(valid->rgbValidationData, valid->ulValidationDataLength, "ValidationData:");
}

/* Display the uchar with better format */
void tpmw_display_uchar(unsigned char *src, int len, char *header)
{
	int i;
	int new_line;

	if (header != NULL)
		printf("%s\n", header);

	for (i = 0; i < len; i++)
	{
		if ((i+1) % TPMW_NUM_PER_LINE != 0)
		{
			printf("%02x ", src[i]);
			new_line = 0;
		}
		else
		{
			printf("%02x\n", src[i]);
			new_line = 1;
		}
	}

	if (new_line == 0)
		printf("\n");
}

/* Generate the nonce locally */
int tpmw_generate_nonce(unsigned char *nonce)
{
	TSS_RESULT	result;
	BYTE            *prgbRandomData;

        result = Tspi_TPM_GetRandom(hTPM,
                                TPMW_NONCE_LEN,
                                &prgbRandomData);
        if (result != TSS_SUCCESS)
        {
                printf("Tspi_TPM_GetRandom failed [%s]\n",
			Trspi_Error_String(result));
		return -1;
        }

	memcpy(nonce, prgbRandomData, TPMW_NONCE_LEN);
	return 0;
}

/* Get the PCR value based on the PCR mask */
int tpmw_get_pcr_value(void)
{
	int i;
        UINT32 ulPcrLen;
        BYTE *rgbPcrValue;
	TSS_RESULT result;

        for(i = 0; i < TPMW_PCR_NUM_MAX; i++)
        {
		if (tpmw_pcr_mask[i] == 1)
		{
                	result = Tspi_TPM_PcrRead(hTPM, i, &ulPcrLen, &rgbPcrValue);
                	if (result != TSS_SUCCESS)
                	{
                        	printf("Tspi_TPM_PcrRead failed for PCR [%u] [%s]\n",
                                	i, Trspi_Error_String(result));
				return -1;
                	}

                	/* Copy the value into static mem */
                	if (ulPcrLen != TPMW_PCR_LEN)
                	{
                        	printf("daveti: Is this possible?\n");
				return -1;
			}

			memcpy(tpmw_pcr_value[i], rgbPcrValue, TPMW_PCR_LEN);
		}
        }

	return 0;
}

/* For tpmd */

/* Generate the fake AT reply - for UT */
void tpmw_generate_fake_at_rep(at_rep *rep)
{
	/* Hard code the reply to be all zeros */
	memset(rep, 0, sizeof(at_rep));

	/* Make the header */
	rep->header[0] = 'a';
	rep->header[1] = 't';
	rep->header[2] = 'p';
}

/* Get the quote using AIK */
TSS_VALIDATION *tpmw_get_quote_with_aik(void)
{
	TSS_RESULT result;
	TSS_HPCRS hPcrComposite;
	TSS_VALIDATION valid;
	TSS_VALIDATION *rtn = NULL;
	int i;

        /* Create the PCR Composite object for quote */
        result = Tspi_Context_CreateObject(hContext,
                                        TSS_OBJECT_TYPE_PCRS,
                                        0,
                                        &hPcrComposite);
        if (result != TSS_SUCCESS)
        {
                printf("Tspi_Context_CreateObject failed for PCR Composite [%s]\n",
                        Trspi_Error_String(result));
		return NULL;
        }

        /* Set the quoted PCR index */
        for (i = 0; i < TPMW_PCR_NUM_MAX; i++)
        {
		if (tpmw_pcr_mask[i] == 1)
		{
                	result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, i);
                	if (result != TSS_SUCCESS)
                	{
                        	printf("Tspi_PcrComposite_SelectPcrIndex failed for index [%d] [%s]\n",
                                	i, Trspi_Error_String(result));
                        	rtn = NULL;
                        	goto close;
			}
                }
        }

        /* Set the input for validation struct */
        valid.ulExternalDataLength = TPMW_NONCE_LEN;
        valid.rgbExternalData = tpmw_nonce;

        /* Do the damn quote */
        result = Tspi_TPM_Quote(hTPM,                           /* in */
                                hIdentKey,                      /* in */
                                hPcrComposite,                 /* in */
                                &valid);        /* in, out */
        if (result != TSS_SUCCESS)
        {
                printf("Tspi_TPM_Quote failed [%s]\n", Trspi_Error_String(result));
                rtn = NULL;
                goto close;
        }

	/* Save the validation */
	rtn = (TSS_VALIDATION *)malloc(sizeof(TSS_VALIDATION));
	memcpy(rtn, &valid, sizeof(TSS_VALIDATION));

close:
	Tspi_Context_CloseObject(hContext, hPcrComposite);
	return rtn;
}

/* Generate the AT reply based on validation struct */
void tpmw_generate_at_rep(at_rep *rep, TSS_VALIDATION *valid)
{
	/* Make the header */
	rep->header[0] = 'a';
	rep->header[1] = 't';
	rep->header[2] = 'p';

	/* Copy the data */
	if (valid->ulDataLength != AT_DATA_LEN)
		printf("tpmw - Error: data len [%d] is different with "
			"AT reply data len [%d]\n",
			valid->ulDataLength,
			AT_DATA_LEN);
	memcpy(rep->data, valid->rgbData, AT_DATA_LEN);

	/* Copy the signature */
	if (valid->ulValidationDataLength != AT_SIG_LEN)
		printf("tpmw - Error: signature len [%d] is different "
			"with AT reply signature len [%d]\n",
			valid->ulValidationDataLength,
			AT_SIG_LEN);
	memcpy(rep->sig, valid->rgbValidationData, AT_SIG_LEN);
}

/* For arpsecd */

/* Load the TPM DB entry into tpmw */
void tpmw_load_db_entry(unsigned char *pcr_mask, unsigned char *pcr_value, int pcr_value_len, unsigned char *key, int key_len)
{
	/* Save the PCR mask */
	memcpy(tpmw_pcr_mask, pcr_mask, TPMW_PCR_NUM_MAX);

	/* Save the PCR value for future verification */
	tpmw_generate_pcr_hash_buf(pcr_value, pcr_value_len);

	/* Save the AIK pub key for signature verification */
	if (tpmw_aik_pub_key != NULL)
		free(tpmw_aik_pub_key);
	tpmw_aik_pub_key = (unsigned char *)malloc(key_len);
	memcpy(tpmw_aik_pub_key, key, key_len);
}

/* Generate the AT request */
int tpmw_generate_at_req(at_req *req)
{
	int rtn;

	/* Make the header */
	req->header[0] = 'a';
	req->header[1] = 't';
	req->header[2] = 'q';

	/* Generate the nonce */
	rtn = tpmw_generate_nonce(tpmw_nonce);
	if (rtn != 0)
	{
		printf("tpmw - Error: tpmw_generate_nonce\n");
		return -1;
	}
		
	/* Save the nonce in the request */
	memcpy(req->nonce, tpmw_nonce, TPMW_NONCE_LEN);

	/* Write the PCR mask */
	memcpy(req->pcr_list, tpmw_pcr_mask, TPMW_PCR_NUM_MAX);

	return 0;
}

/* Init the PCR hash buf for future PCR digest verification */
void tpmw_init_pcr_hash_buf(void)
{
	/* Allocate the memory */
	tpmw_pcr_hash_buf = (unsigned char *)calloc(1,
					2 + TPMW_PCR_BYTE + 4 + TPMW_PCR_LEN * TPMW_PCR_NUM_MAX);
	/* Write the header */
	*(UINT16 *)tpmw_pcr_hash_buf = htons(TPMW_PCR_BYTE);

	/* To be perfect */
	tpmw_pcr_hash_len = 0;
}

/* Generate the complete PCR hash buf based on PCR mask and value */ 
void tpmw_generate_pcr_hash_buf(unsigned char *pcr_value, int len)
{
	int i;
	int pcr_num = 0;
	unsigned char *bp;

	/* Write the magic first 8 bytes */
	for (i = 0; i < TPMW_PCR_NUM_MAX; i++)
	{
		if (tpmw_pcr_mask[i] == 1)
		{
			pcr_num++;
			/* Magic operation for pcr buf...*/
			tpmw_pcr_hash_buf[2+(i/8)] |= 1 << (i%8);
		}
	}

        bp = tpmw_pcr_hash_buf + 2 + TPMW_PCR_BYTE;
        *(UINT32 *)bp = htonl(TPMW_PCR_LEN * pcr_num);
        bp += sizeof(UINT32);

	/* Write the PCR value */
	memcpy(bp, pcr_value, len);
	bp += len;

	/* Save the length of the hash */
        tpmw_pcr_hash_len = (int)(bp - tpmw_pcr_hash_buf);
}

/* Verify the signature by loading AIK pub key and computing hash */
int tpmw_verify_signature(unsigned char *data, unsigned char *sig)
{
	int		rtn;
	TSS_RESULT	result;
	TSS_HHASH	hHash;
        UINT32		initFlags = TSS_KEY_TYPE_SIGNING
					| TSS_KEY_SIZE_2048
					| TSS_KEY_NO_AUTHORIZATION
                                        | TSS_KEY_NOT_MIGRATABLE;

	/* Assume here:
	 * validation.rgbValidationData = SHA1(validation.rgbData)
	 */

	/* Create the hash data used for signature verification */
        result = Tspi_Context_CreateObject(hContext,
                                	TSS_OBJECT_TYPE_HASH,
                                	TSS_HASH_SHA1,
                                	&hHash);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Context_CreateObject failed for hash data [%s]\n",
			Trspi_Error_String(result));
		return -1;
	}

	/* Set the hash data the same as data */
        result = Tspi_Hash_UpdateHashValue(hHash,
					AT_DATA_LEN,
					(BYTE *)data);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Hash_UpdateHashValue failed for hash data [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close2;
	}

	/* Create verification key */
	result = Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_RSAKEY,
					initFlags,
					&hKey);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Context_CreateObject failed hKey [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close2;
	}

	/* Load the AIK pub key into the verification key */
	result = Tspi_SetAttribData(hKey,
				TSS_TSPATTRIB_KEY_BLOB,
				TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				tpmw_aik_pub_key_len,
				tpmw_aik_pub_key);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_SetAttribData failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Verify the damn quote using AIK pub key */
	result = Tspi_Hash_VerifySignature(hHash,              /* in */
                          		hKey,                /* in */
                          		AT_SIG_LEN,     /* in */
                          		sig);          /* in */
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Hash_VerifySignature failed [%s]\n", Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	rtn = 0;
close:
	Tspi_Context_CloseObject(hContext, hKey);
close2:
	Tspi_Context_CloseObject(hContext, hHash);
	return rtn;
}


