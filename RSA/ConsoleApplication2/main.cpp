#include <stdio.h>                   // main.cpp  
#include <openssl/evp.h>  
#include <stdlib.h>  
#include <openssl/rand.h>  
#include <openssl/rsa.h>  
#include <openssl/pem.h>  
#include <string.h>  
#include<streambuf>

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


using namespace std;
template<typename T>
class P
{
public:
	P(int n = 0){ num = n; }
	P(const P<T>& copy){ num = copy.num; }
	friend ostream&operator<< <>(ostream& out, P<T> & obj);//friend ostream&operator<< <T>(ostream& out,P<T> & obj);  
private:
	int num;
};
template<typename T>
ostream&operator<< (ostream& out, P<T> & obj)
{
	out << obj.num;
	return out;

}



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

	int fd2 = open("d://test1.cpp", O_RDWR | O_CREAT);

	char buf[1024] = "123456789";

	size_t nwrite = write(fd2, buf, 1024);

	close(fd2);

	
	//d 35089110059338646129184322637454169994585290733787694469066335868507167798590523586912076087534848380192757940547258371484813636261958490220813855163748885325156442794494043642392073045883458948926257243583685126287929211976414260631348731809062056162405927855076578592840391914563685388932643148724472168273
	unsigned int e = 65537;
	const char* n = "17940310759273821186091581584347644044532110653611418699399056760535726181949455909144061033504176046416709472278996844000450948857220538550053615420925570802434732707421445671477723887387914317469612014260650051468786981006855259611418439128933224994326497684896586953029899510145805760405843701781804218344837909274948803595405675987967173096900321030771190203653250898572215814821822532134516026113119288551182967270982365478632519526369244532509171907932412232634363383953554099707402311802908794637876801835946089556255898817291537076439262510079546459483035933240627147365281467516137748986227401106139071070769";
	//char psz_encode[4096] = "tAMMOxUDnlSga0k2KQ1JBrcvs9wUs+0Q3o/P9yvRfItbkEGEbnXkcNXByEKhagJ3zqMA9gS0EVIRB3o0kZmcYGY5N6XvJRcydwwEcJHieC/RVEk7cV/h1Z+tTlWT0ooXKiY+2pbfee59+xvj2d4nu0dgc3ACWXCPaYTYFoM/R5s=";// { 0 };
	
	char psz_encode[8094] = "O6cgtIkNkhvTrhfXgyi8xRUEZWYMK9QzjTxQ7SolNgUJA9yNJtAFTEdLXsr8rHhQEk8o5M60zGInTuZUv21J9RhbtnESFvGsJbeqLAyyr9BfeZ7J4ydrB6nk8f3+Iu71BpwLxff1q7cn8Nah3eGBAFboAk56PE3Sn3qmXe3TdTJc2IpyV4otmB9il9+RH8XzJ1iSMMwlDMOtUEfIK5kbG4dhoOBs/2tat1RewXko/kwzzVqLHZj2UD5dbiFxQeJZSJyA4XfOhB1qYXH9eKIQhorD0gYG/sLtKb5EDZVn5umFSxU7mKFblTNEncZpZhm2bgLldteU/AsbKSv7PBCw7gJJkPz6TvNDmHy9mtMzXv4G/pZnFn8q5BjmC/Ql0WgspKVvaOaXcNIC40xRsF0v9df89lheVGenwOVm3dHgrqvFltDyR9GCnlRDuTT3rpoelgcmaLwvU5940F5h0d321TZHXwc5QRYMS7CaTV3Ose7aQ/Byy0tubAdFqoMDEDmDGCjumuUSU3VjkubXHsOuGJWPnkIbvHdv+wrXYru2E3JxB8GecSOAvA8h5hvFHlXuv9LQRUeOfVUeKKq2PnY8/JkqjBSITHyOg18p+RyuU90kDWAze0tIRRQSAVRqhrKolF1VCEi96+jgZEzIqhztAIhFCVaewXqh+CCTqyMt4G5zhzPy94nnvKE6vqmi9D33JmWWJyfwsh6xpYyY2AUopXDS0SYvPr5K+LhrAUTn2DRabO7Gc7+Otl6FaQLvMW1MmVLa/5xCQ0/PrH6hLgVqsZcSSXtcmN7a6+pxUrldSLQGMYoYCbUq+NkhSsTA3gwA+h2Mtx7N/pgnSfTccpc1hRR6RINdlIhZr0TbcZawpFhfNm9J6mzocr2hBkzuPkyyymwjv4CierE9rLlZHm0mIvvnW8QPYigYcDJ1wjbfd1j6FRH/SCl3U5w3h/u76seW9BEVrYUOxtA0xAm3ft7AJq+YbpDP4XnaaLwCxFKsFYMTq++fCEH09kJwzVppSrpO";
	
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