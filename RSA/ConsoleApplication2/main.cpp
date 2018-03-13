#include <stdio.h>                   // main.cpp  
#include <openssl/evp.h>  
#include <stdlib.h>  
#include <openssl/rand.h>  
#include <openssl/rsa.h>  
#include <openssl/pem.h>  
#include <string.h>  


//#ifdef WIN32  
//#pragma comment(lib, "libeay32MDd.lib")  
//#pragma comment(lib, "ssleay32MDd.lib")  
//#endif  

#ifdef WIN32  
#pragma comment(lib, "libcrypto64MDd.lib")  
#pragma comment(lib, "libssl64MDd.lib")  
#endif
#ifdef __cplusplus
extern "C"{
#endif
#include "applink.c"
#ifdef __cplusplus

}
#endif



static int base64_encode(unsigned char *str, int str_len, char *encode, int *encode_len)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	if (!str || !encode)
	{
		return 1;
	}

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, str, str_len); //encode  
	if (BIO_flush(b64));
	BIO_get_mem_ptr(b64, &bptr);
	if (bptr->length > *encode_len)
	{
		printf("encode_len too small\n");
		return 1;
	}
	*encode_len = bptr->length;
	memcpy(encode, bptr->data, bptr->length);
	//  write(1,encode,bptr->length);  
	BIO_free_all(b64);
	return 0;
}

static int base64_decode(const char* input, int inLen, unsigned char* output, int *outLen)
{
	if (!input || !output)
	{
		return -1;
	}

	char *psz_tmp = (char*)malloc(inLen + 1);
	if (!psz_tmp)
	{
		abort();
	}
	memset(psz_tmp, 0, inLen + 1);

	psz_tmp[inLen] = '\n';      // Openssl demand to have '\n' to end the string.  
	memcpy(&psz_tmp[0], input, inLen);
	memset(output, 0, *outLen);
	BIO * b642 = BIO_new(BIO_f_base64());
	BIO_set_flags(b642, BIO_FLAGS_BASE64_NO_NL);
	BIO * bmem2 = BIO_new_mem_buf(&psz_tmp[0], inLen + 1);
	// should not use the input directly, the follow is wrong  
	//BIO * bmem2 = BIO_new_mem_buf( ( char * )input, inLen+1);  
	bmem2 = BIO_push(b642, bmem2);
	*outLen = BIO_read(bmem2, output, inLen);
	BIO_free_all(bmem2);
	return 0;
}

int main(int argc, char **argv)  
{  
	
	//d 35089110059338646129184322637454169994585290733787694469066335868507167798590523586912076087534848380192757940547258371484813636261958490220813855163748885325156442794494043642392073045883458948926257243583685126287929211976414260631348731809062056162405927855076578592840391914563685388932643148724472168273
	unsigned int e = 65537;
	const char* n = "20721543166547400083143220518213657650007942665125967641807454564718370505467213377642716916744477246938739414870590880371396797974266382002066978746053764705284975920295834097987587685207713954711315323986862714824385078098890402885608787493142393719386619261139755421073097249392036660905526460559564607118402649152016905947142617067097085309487657756246207278730006415027993017082335087799767710219586022320949816497261658339916735758974282813641386600074926510795139083963730713201600002922289962293345293021167906670850257101573320854618164127095255302022466341883013558380302973821546943236303424056517254002103";
	//char psz_encode[4096] = "tAMMOxUDnlSga0k2KQ1JBrcvs9wUs+0Q3o/P9yvRfItbkEGEbnXkcNXByEKhagJ3zqMA9gS0EVIRB3o0kZmcYGY5N6XvJRcydwwEcJHieC/RVEk7cV/h1Z+tTlWT0ooXKiY+2pbfee59+xvj2d4nu0dgc3ACWXCPaYTYFoM/R5s=";// { 0 };
	
	char psz_encode[8094] = "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";
	
	unsigned char psz_decode[8094] = { 0 };
	int i_outlen = 8094;
	if (0 != base64_decode(psz_encode, strlen(psz_encode), psz_decode, &i_outlen))
	{
		printf("decode error!");
		return -1;
	}

	//构建RSA数据结构  
	RSA* _pub_key = RSA_new();
	BIGNUM* bne = BN_new();
	BIGNUM* bnn = BN_new();

	
	/*_pub_key->e = bne;
	_pub_key->n = bnn;*/
	BN_dec2bn(&bnn, n);

	BN_set_word(bne, e);

	RSA_set0_key(_pub_key, bnn, bne, NULL);
	RSA_print_fp(stdout, _pub_key, 0);
	int out_len = RSA_size(_pub_key);
	unsigned char * out = (unsigned char *)malloc(out_len);
	if (NULL == out)
	{
		printf("pubkey_decrypt:malloc error!\n");
		return -1;
	}
	memset((void *)out, 0, out_len);
	int MAX_ENCRYPT_BLOCK = 256;
	int offSet = 0;
	int i = 0;

	while (i_outlen - offSet > 0) {
		unsigned char temp[256] = { 0 };
		
		if (i_outlen - offSet > MAX_ENCRYPT_BLOCK) {
			memcpy(temp, psz_decode + offSet, MAX_ENCRYPT_BLOCK);
		}
		else {
			memcpy(temp, psz_decode + offSet, i_outlen - offSet);
		}
		memset((void *)out, 0, out_len);
		int ret = RSA_public_decrypt(sizeof(temp), temp, out, _pub_key, RSA_PKCS1_PADDING);
		printf("%s\n", out);
		i++;
		offSet = i * MAX_ENCRYPT_BLOCK;
	}


	


	
	return 0;
}  