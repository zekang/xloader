/*
+----------------------------------------------------------------------+
| PHP Version 5                                                        |
+----------------------------------------------------------------------+
| Copyright (c) 1997-2015 The PHP Group                                |
+----------------------------------------------------------------------+
| This source file is subject to version 3.01 of the PHP license,      |
| that is bundled with this package in the file LICENSE, and is        |
| available through the world-wide-web at the following url:           |
| http://www.php.net/license/3_01.txt                                  |
| If you did not receive a copy of the PHP license and are unable to   |
| obtain it through the world-wide-web, please send a note to          |
| license@php.net so we can mail you a copy immediately.               |
+----------------------------------------------------------------------+
| Author:  wanghouqian <whq654321@126.com>                             |
+----------------------------------------------------------------------+
*/
/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/php_rand.h"
#include "ext/standard/php_string.h"
#include "ext/standard/md5.h"
#include "php_xloader.h"
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <fcntl.h>
#include "zend_language_scanner.h"
#include "php_streams.h"
#include "aes.h"

ZEND_DECLARE_MODULE_GLOBALS(xloader);

#define DECRPTY_FILE_BUF_SIZE 102400
#define AES_256_CBC_BLOCK_SIZE 16
#define AES_256_CBC_KEY_SIZE 32
#define AES_256_CBC_IV_SIZE 16
#define PIPE_SIZE 65535
typedef enum {
	xloader_encrypt,
	xloader_decrypt
}xloader_encrypt_type;

/* True global resources - no need for thread safety here */
static int le_xloader;

//__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");

#define ENCRYPT_FILE_HEADER_SIGN "\x2a\x1c\xa3\x0b\xf2\xf1\x60\x1f"
#define ENCRYPT_FILE_HEADER_SIGN_LEN 8
#define LICENSE_SECRET_KEY "\x1a\x2c\xb3\x1b\xe1\x11\x21\x1f\xbc\x1e\xa5\x6b\x1a\xd1\x6d\x2d\x3f\xfd\xae\xab\x7c\x9d\x8a\x4c\x2b\x4f\x6c\xcc\xbb\xf0\xa0\x89"
#define LICENSE_SECRET_KEY_LEN 32
#define IV_KEY "\x89\x2f\xc4\x2c\xd9\xe5\x21\x1f\xbc\x22\xa5\xa5\x1a\xd1\x6d\x2d"
#define IV_KEY_LEN 16
#define VALIDATE_TOKEN "\xc9\xef\xc4\x2c\xd9\xe5\x23\x6f\xdc\x32\x45\x75\x9a\x51\x6d\x2c"
#define VALIDATE_TOKEN_LEN 16
#define LETTERS "ABCDEFGHIJKLMNOPRSTUVWXYZ"
#define CHECK_LICENSE  \
	if(!XLOADER_G(license)){ \
		zend_error(E_ERROR,"No license or license error!");\
		goto NOT_ALLOWED;\
	}\
	if(!XLOADER_G(network_card_status)){\
		zend_error(E_ERROR,"Not allowed run at this computer!");\
		goto NOT_ALLOWED;\
	}\
	if(XLOADER_G(expire) > 0 && XLOADER_G(expire) < time(NULL)){\
		zend_error(E_ERROR,"This program was expired!");\
		goto NOT_ALLOWED;\
	}
#define CHECK_USE_STACK_OR_HEAP(code_size,real_size) \
	if(code_size  >  DECRPTY_FILE_BUF_SIZE){ \
		bufHeap = emalloc(code_size + AES_256_CBC_BLOCK_SIZE);\
		if(bufHeap==NULL){\
			break;\
		}\
		memset(bufHeap,0,code_size);\
		buf = bufHeap;\
	}else{\
		buf = bufStack;\
	}\
	int real_size = code_size - ENCRYPT_FILE_HEADER_SIGN_LEN;
#define DECRYPT_CODE \
	if(get_file_iv(file_handle->filename,iv TSRMLS_CC )<0){\
		break;\
	}\
	data_len = xloader_aes_cbc(xloader_decrypt,XLOADER_G(license)->secretKey,USER_SECRET_KEY_LEN,iv,AES_256_CBC_IV_SIZE,buf,body_len TSRMLS_CC);\
	if(data_len<0){\
		break;\
	}
		
#define CACHE_PUT(key,data) \
	if(XLOADER_G(cache_enable)){ \
		if(!XLOADER_G(cache)){ \
			XLOADER_G(cache) = (HashTable *)pemalloc(sizeof(HashTable), 1);\
			if (XLOADER_G(cache)){\
				zend_hash_init(XLOADER_G(cache), 8, NULL,NULL, 1);\
			}\
		}\
		if (XLOADER_G(cache)){\
			zend_hash_add(XLOADER_G(cache),key,strlen(key)+1,data,strlen(data)+1,NULL);\
		}\
	}
#define CACHE_GET(key,data)  (XLOADER_G(cache)&& zend_hash_find(XLOADER_G(cache),key,strlen(key)+1,(void **)&data)==SUCCESS)

static zend_op_array* (*old_compile_file)(zend_file_handle*, int TSRMLS_DC);


/*{{{ static int md5(char *str,int strlen,char *salt,int salt_len,char *buf,int raw)
 */
static int md5(char *str,int strlen,char *salt,int salt_len,char *buf,int raw)
{
	PHP_MD5_CTX context;
	unsigned char digest[16];
	if(buf==NULL){
		return -1;
	}
	buf[0] = '\0';
	PHP_MD5Init(&context);
	PHP_MD5Update(&context, str, strlen);
	if(salt &&salt_len>0){
		PHP_MD5Update(&context, salt, salt_len);
	}
	PHP_MD5Final(digest, &context);
	if(raw){
		memcpy(buf,digest,sizeof(digest));
	}else{
		make_digest_ex(buf, digest, 16);
	}
	return 0;
}
/*}}}*/

/*{{{ int base32_decode(const uchar *encoded,int length, uchar **return_value TSRMLS_DC)
 */
int base32_decode(const uchar *encoded,int length, uchar **return_value TSRMLS_DC)
{
		int buffer = 0;
		int bitsLeft = 0;
		int count = 0;
		const uchar *ptr;
		uchar *result ;
		result = (uchar *) safe_emalloc(length,1,1);
		for (ptr = encoded;  *ptr; ++ptr) {
				uchar ch = *ptr;
				if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
						continue;
				}
				buffer <<= 5;
				if (ch == '0') {
						ch = 'O';
				} else if (ch == '1') {
						ch = 'L';
				} else if (ch == '8') {
						ch = 'B';
				}
				if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
						ch = (ch & 0x1F) - 1;
				} else if (ch >= '2' && ch <= '7') {
						ch -= '2' - 26;
				} else {
						efree(result);
						return -1;
				}
				buffer |= ch;
				bitsLeft += 5;
				if (bitsLeft >= 8) {
						result[count++] = buffer >> (bitsLeft - 8);
						bitsLeft -= 8;
				}
		}
		result[count] = '\000';
		*return_value = result;
		return count;
}
/*}}}*/

/*{{{ int base32_encode(const uchar *data, int length, uchar **return_value TSRMLS_DC)
 */
int base32_encode(const uchar *data, int length, uchar **return_value TSRMLS_DC)
{
		uchar * result;
		if (length < 0 || length > (1 << 28)) {
				return -1;
		}
		int count = 0;
		int bufSize = ((length+4) /5 *8) + 1;
		result = (uchar *) safe_emalloc(bufSize,sizeof(char),1);
		if (length > 0) {
				int buffer = data[0];
				int next = 1;
				int bitsLeft = 8;
				while (count<bufSize && (bitsLeft > 0 || next < length)) {
						if (bitsLeft < 5) {
								if (next < length) {
										buffer <<= 8;
										buffer |= data[next++] & 0xFF;
										bitsLeft += 8;
								} else {
										int pad = 5 - bitsLeft;
										buffer <<= pad;
										bitsLeft += pad;
								}
						}
						int index = 0x1F & (buffer >> (bitsLeft - 5));
						bitsLeft -= 5;
						result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
				}
		}
		if (count < bufSize) {
				result[count] = '\000';
		}
		*return_value = result;
		return count;
}
/*}}}*/

int xloader_aes_cbc(xloader_encrypt_type type,char *key,int key_len,char *iv,int iv_len,char *data,int data_len TSRMLS_DC)/*{{{*/
{
	int retval = 0,i;
	aes_context aes;
	char key_tmp[64]={0};
	char iv_tmp[32]={0};
	memcpy(key_tmp,key,AES_256_CBC_KEY_SIZE);
	int blocks = ((data_len - 1) / AES_256_CBC_BLOCK_SIZE) + 1 ;
	
	if(type == xloader_encrypt){
		aes_setkey_enc( &aes, key_tmp, 256 );
	}else{
		aes_setkey_dec( &aes, key_tmp, 256 );
	}
	
	for(i=0;i<blocks;i++) {
		memcpy(iv_tmp,iv,AES_256_CBC_IV_SIZE);
		if(type == xloader_encrypt){
			aes_crypt_cbc(&aes, AES_ENCRYPT, AES_256_CBC_BLOCK_SIZE, iv_tmp, data+i*AES_256_CBC_BLOCK_SIZE, data+i*AES_256_CBC_BLOCK_SIZE);
		}else{
			aes_crypt_cbc(&aes, AES_DECRYPT, AES_256_CBC_BLOCK_SIZE, iv_tmp, data+i*AES_256_CBC_BLOCK_SIZE, data+i*AES_256_CBC_BLOCK_SIZE);
		}
	}

	return blocks * AES_256_CBC_BLOCK_SIZE;
}
/*}}}*/


/*{{{ create_licence(uchar **return_value,const char *secretKey ,int secretKey_len ,const char *HWaddr,int HWaddr_len,int expire,const char *name,int name_len TSRMLS_DC)
 */
int create_licence(uchar **return_value,const char *secretKey ,int secretKey_len ,const char *HWaddr,int HWaddr_len,int expire,const char *HWname,int HWname_len TSRMLS_DC)
{
	xloader_license  license ={0};
	char iv[AES_256_CBC_IV_SIZE] = {0};
	int size = sizeof(iv);
	int retval = 0;
	int result = 0;
	if(return_value == NULL){
		retval = -10;
		goto END;
	}
	if(secretKey==NULL || secretKey_len < 1 || secretKey_len > USER_SECRET_KEY_LEN ){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "secretKey can't be empty or too long");
		retval = -1;
		goto END;
	}
	if(HWaddr==NULL || HWaddr_len < 1 || HWaddr_len > USER_HWADDR_LEN ){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "HWaddr can't be empty or too long");
		retval = -2;
		goto END;
	}
	if(HWname==NULL || HWname_len < 1 || HWname_len > USER_HWNAME_LEN ){
		retval = -3;
		goto END;
	}
	memcpy(license.secretKey,secretKey,secretKey_len);
	memcpy(license.HWaddr,HWaddr,HWaddr_len);
	memcpy(license.HWname,HWname,HWname_len);
	memcpy(license.token,VALIDATE_TOKEN,VALIDATE_TOKEN_LEN);
	license.expire = expire;
	while (size) {
		iv[--size] = (char) (255.0 * php_rand(TSRMLS_C) / RAND_MAX);
	}
	char data_s[1024] = {0};
	char final [1024] = {0};
	memcpy(data_s, (char *)&license, XLOADER_LICENCE_SIZE);
	int  data_size = xloader_aes_cbc(xloader_encrypt,LICENSE_SECRET_KEY,LICENSE_SECRET_KEY_LEN,iv,AES_256_CBC_IV_SIZE,data_s,XLOADER_LICENCE_SIZE TSRMLS_CC);
	if(data_size < 0){
		retval = -4;
		goto END;
	}
	int rand = php_rand(TSRMLS_C);
	RAND_RANGE(rand, 0, 25, PHP_RAND_MAX);
	char first = LETTERS[rand];
	int mod = ( first  - 65 ) % 10 + 2;
	int i,j,k=0;
	final[k++] = first;

	for(i=0,j=0;i<data_size;i++){
		if(i>0 && j<sizeof(iv) && (i % mod )==0){
			final[k++] = iv[j++];
		}
		final[k++] = data_s[i];
	}
	retval = base32_encode(final,k,return_value TSRMLS_CC);
END:
	return retval;
}
/*}}}*/

/*{{{  int parse_licence(xloader_licence *return_value,char *pLicence ,int pLicence_lenTSRMLS_DC)
 */
int parse_licence(xloader_license *return_value,uchar *pLicence,int pLicence_len TSRMLS_DC)
{
	int retval = 0;
	uchar *decode_str = NULL;
	int decode_str_len = 0;
	if(return_value == NULL || pLicence == NULL){
		retval = -1;
		goto END;
	}
	decode_str_len =  base32_decode(pLicence,pLicence_len,&decode_str TSRMLS_CC);
	if(decode_str_len ==-1){
			retval = -2;
			goto END;
	}
	char first = decode_str[0];
	int mod = ( first  - 65 ) % 10 + 2;
	char *enc_str = decode_str + 1;
	int i,j,k,m;
	char iv[AES_256_CBC_IV_SIZE]={0};
	char data_s[1024]={0};
	for(i=0,j=0,k=0,m=0;i<decode_str_len-1;i++){
		if(k>0 && j<sizeof(iv) && (k % mod) ==0){
				iv[j++] = enc_str[i];
				k=0;
		}else{
			data_s[m++] = enc_str[i];
			k++;
		}
	}
	//正常应该是256
	if( m > 980){
		retval = -3;
		goto END;
	}
	int  data_size = xloader_aes_cbc(xloader_decrypt,LICENSE_SECRET_KEY,LICENSE_SECRET_KEY_LEN,iv,AES_256_CBC_IV_SIZE,data_s,m TSRMLS_CC);
	if(data_size < 0){
		retval = -4;
		goto END;
	}
	memcpy(return_value,data_s,XLOADER_LICENCE_SIZE);
	if(memcmp(return_value->token,VALIDATE_TOKEN,VALIDATE_TOKEN_LEN)){
		retval = -5;
	}
END:
	if(decode_str){
		efree(decode_str);
	}
	return retval;
}
/*}}}*/

int get_file_iv(const char *file,char *out TSRMLS_DC)/*{{{*/
{
	char *ret=NULL;
	size_t ret_len = 0;
	int retval  = 0;
	do{
		php_basename(file, strlen(file), NULL, 0, &ret, &ret_len TSRMLS_CC);
		if(!ret){
			retval = -1;
			break;
		}
		retval = md5(ret,ret_len,IV_KEY,IV_KEY_LEN,out,1);
	}while(0);
	if(ret){
		efree(ret);
	}
	return retval;
}/*}}}*/


int filter_code_comments(char *filename, zval *retval TSRMLS_DC)/*{{{*/
{
    zend_lex_state original_lex_state;
    zend_file_handle file_handle = {0};

#if PHP_API_VERSION > 20090626

    php_output_start_default(TSRMLS_C);

    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = filename;
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

    zend_save_lexical_state(&original_lex_state TSRMLS_CC);
    if (open_file_for_scanning(&file_handle TSRMLS_CC) == FAILURE) {
        zend_restore_lexical_state(&original_lex_state TSRMLS_CC);
        php_output_end(TSRMLS_C);
        return -1;
    }

    zend_strip(TSRMLS_C);

    zend_destroy_file_handle(&file_handle TSRMLS_CC);
    zend_restore_lexical_state(&original_lex_state TSRMLS_CC);

    php_output_get_contents(retval TSRMLS_CC);
    php_output_discard(TSRMLS_C);

#else

    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = filename;
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

    zend_save_lexical_state(&original_lex_state TSRMLS_CC);
    if (open_file_for_scanning(&file_handle TSRMLS_CC) == FAILURE) {
        zend_restore_lexical_state(&original_lex_state TSRMLS_CC);
        return -1;
    }

    php_start_ob_buffer(NULL, 0, 1 TSRMLS_CC);

    zend_strip(TSRMLS_C);

    zend_destroy_file_handle(&file_handle TSRMLS_CC);
    zend_restore_lexical_state(&original_lex_state TSRMLS_CC);

    php_ob_get_buffer(retval TSRMLS_CC);
    php_end_ob_buffer(0, 0 TSRMLS_CC);

#endif

    return 0;
}/*}}}*/

static char *get_mac_address(char *networkcard,char *output) /*{{{*/
{
    char netfile[128] = { 0 }, cmd[128] = { 0 }, buf[128] = { 0 };
    if(output == NULL)
    {
    	return NULL;
    }
    FILE *fp;
    char *retbuf, *curr, *last;
    snprintf(netfile, 128, "/sys/class/net/%s/address", networkcard);
    if (access((const char *)netfile, R_OK) != 0) { /* File not exists */
        return NULL;
    }
    snprintf(cmd, 128, "cat %s", netfile);
    fp = popen(cmd, "r");
    if (!fp) {
        return NULL;
    }
    retbuf = fgets(buf, 128, fp);
    for (curr = buf, last = NULL; *curr; curr++) {
        if (*curr != '\n') {
            last = curr;
        }
    }
    if (!last) {
        return NULL;
    }
    for (last += 1; *last; last++) {
        *last = '\0';
    }
	php_strtoupper(buf,sizeof(buf));
    pclose(fp);
    strcpy(output,buf);
    return output;
}/*}}}*/

zend_op_array *xloader_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC)/*{{{*/
{
	int fd = 0;
	char  bufStack[DECRPTY_FILE_BUF_SIZE + AES_256_CBC_BLOCK_SIZE]= {0};
	char *bufHeap = NULL;
	char *buf = NULL;
	struct stat stat_buf;
	char *code=NULL;
	size_t code_len;
	int pipefd[2] = {0};
	char iv[LICENSE_SECRET_KEY_LEN] ={0};
	int close_read_pipe = 1,data_len,need_free_handler=0,use_fp_handle = 0;
	FILE *ptmp = NULL;
	do{
		fd = open(file_handle->filename,O_RDONLY);
		if(fd == -1){
			if(zend_stream_fixup(file_handle,&code,&code_len TSRMLS_CC) == FAILURE){
				break;
			}
			if(memcmp(code,ENCRYPT_FILE_HEADER_SIGN,ENCRYPT_FILE_HEADER_SIGN_LEN)!=0){
				break;
			}
			need_free_handler = 1;
			CHECK_LICENSE
			
			if( file_handle->opened_path && CACHE_GET(file_handle->opened_path,buf)){
			}else{
				CHECK_USE_STACK_OR_HEAP(code_len,body_len)
				memcpy(buf,code+ENCRYPT_FILE_HEADER_SIGN_LEN,code_len);
				DECRYPT_CODE 
				CACHE_PUT(file_handle->opened_path,buf);
			}
		}else{
			if(read(fd,bufStack,ENCRYPT_FILE_HEADER_SIGN_LEN) != ENCRYPT_FILE_HEADER_SIGN_LEN){
				break;
			}
			if(memcmp(bufStack,ENCRYPT_FILE_HEADER_SIGN,ENCRYPT_FILE_HEADER_SIGN_LEN)!=0){
				break;
			}
			CHECK_LICENSE
			
			if(CACHE_GET(file_handle->filename,buf)){
			}else{
				if(fstat(fd,&stat_buf) == -1){
					break;
				}
				CHECK_USE_STACK_OR_HEAP(stat_buf.st_size,body_len)
				if(read(fd,buf,body_len) != body_len){
					break;
				}
				DECRYPT_CODE
				CACHE_PUT(file_handle->filename,buf);
			}
		}
		data_len = strlen(buf);
		if(data_len < PIPE_SIZE){
			if(pipe(pipefd) == -1){
					break;
			}
			fcntl(pipefd[0], F_SETFL, O_NOATIME);
			int flags = fcntl(pipefd[1],F_GETFL);
			flags |= O_NONBLOCK;
			fcntl(pipefd[1],F_SETFL,flags);
		}
		if((pipefd[1] > 0 && write(pipefd[1],buf,data_len) != data_len) || (data_len >= PIPE_SIZE) ){
			ptmp = tmpfile();
			if(ptmp && (fwrite(buf,sizeof(char),data_len,ptmp)==data_len )){
				use_fp_handle = 1;
				rewind(ptmp);
			}else{
				break;
			}
		}
		if (file_handle->type == ZEND_HANDLE_FP) {
			fclose(file_handle->handle.fp);
		}
		if (file_handle->type == ZEND_HANDLE_FD) {
			close(file_handle->handle.fd);
		}
		if(use_fp_handle){
			if(!file_handle->opened_path){
				file_handle->opened_path = expand_filepath(file_handle->filename, NULL TSRMLS_CC);
			}
			file_handle->handle.fp = ptmp;
			file_handle->type = ZEND_HANDLE_FP;
		}else{
			file_handle->type = ZEND_HANDLE_FD;
			file_handle->handle.fd = pipefd[0];
			close_read_pipe = 0;
		}
	}while(0);
	if(need_free_handler){
			int free_filename = file_handle->free_filename ;
			char *opened_path = file_handle->opened_path ;
			file_handle->opened_path = NULL;
			file_handle->free_filename = 0;
			zend_file_handle_dtor(file_handle TSRMLS_CC);
			file_handle->opened_path = opened_path;
			file_handle->free_filename = free_filename;
	}
	if(fd > 0){
		close(fd);
	}
	if(bufHeap){
		efree(bufHeap);
	}

	if(pipefd[1]){
		close(pipefd[1]);
	}
	if(close_read_pipe && pipefd[0]){
		close(pipefd[0]);
	}
    return old_compile_file(file_handle, type TSRMLS_CC);
NOT_ALLOWED:
	if(need_free_handler){
			int free_filename = file_handle->free_filename ;
			char *opened_path = file_handle->opened_path ;
			file_handle->opened_path = NULL;
			file_handle->free_filename = 0;
			zend_file_handle_dtor(file_handle TSRMLS_CC);
			file_handle->opened_path = opened_path;
			file_handle->free_filename = free_filename;
	}
	if(fd > 0){
		close(fd);
	}
	if(bufHeap){
		efree(bufHeap);
	}
	if (file_handle->opened_path) {
		efree(file_handle->opened_path);
		file_handle->opened_path = NULL;
	}
	return NULL;
}
/*}}}*/

/* {{{ arg_info */

ZEND_BEGIN_ARG_INFO_EX(arg_info_xloader_license,0,0,5)
ZEND_ARG_INFO(0,secretKey)
ZEND_ARG_INFO(0,HWaddr)
ZEND_ARG_INFO(0,expire)
ZEND_ARG_INFO(0,HWname)
ZEND_ARG_INFO(0,limit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_info_xloader_encrypt,0,0,3)
ZEND_ARG_INFO(0,secretKey)
ZEND_ARG_INFO(0,file)
ZEND_ARG_INFO(0,outputDir)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arg_info_xloader_clear,0,0,0)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(arg_info_xloader_hardware_address,0,0,1)
ZEND_ARG_INFO(0,HWname)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ xloader_functions[]
 *
 * Every user visible function must have an entry in xloader_functions[].
 */
const zend_function_entry xloader_functions[] = {
	PHP_FE(xloader_license,	arg_info_xloader_license)
	PHP_FE(xloader_encrypt,arg_info_xloader_encrypt)
	PHP_FE(xloader_clear,arg_info_xloader_clear)
	PHP_FE(xloader_hardware_address,arg_info_xloader_hardware_address)
	PHP_FE_END	/* Must be the last line in xloader_functions[] */
};
/* }}} */

/* {{{ xloader_module_entry
 */
zend_module_entry xloader_module_entry = {
	STANDARD_MODULE_HEADER,
	"xloader",
	xloader_functions,
	PHP_MINIT(xloader),
	PHP_MSHUTDOWN(xloader),
	PHP_RINIT(xloader),
	PHP_RSHUTDOWN(xloader),
	PHP_MINFO(xloader),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_XLOADER_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */



#ifdef COMPILE_DL_XLOADER
ZEND_GET_MODULE(xloader)
#endif

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("xloader.enable",      "1", PHP_INI_SYSTEM, OnUpdateBool, enable, zend_xloader_globals, xloader_globals)
    STD_PHP_INI_ENTRY("xloader.cache_enable","1", PHP_INI_SYSTEM, OnUpdateBool, cache_enable, zend_xloader_globals, xloader_globals)
	STD_PHP_INI_ENTRY("xloader.license_path", NULL, PHP_INI_SYSTEM, OnUpdateString, license_path, zend_xloader_globals, xloader_globals)
	STD_PHP_INI_ENTRY("xloader.license_sign", NULL, PHP_INI_SYSTEM, OnUpdateString, license_sign, zend_xloader_globals, xloader_globals)
PHP_INI_END()
/* }}} */

/* {{{ php_xloader_init_globals
 */
static void php_xloader_init_globals(zend_xloader_globals *xloader_globals)
{
	xloader_globals->enable = 1;
	xloader_globals->cache_enable = 1;
	xloader_globals->license_path = NULL;
	xloader_globals->license_sign = NULL;
	xloader_globals->network_card_status = 0;
	xloader_globals->expire = 0;
	xloader_globals->cache = NULL;
	xloader_globals->license = NULL;

}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(xloader)
{
    ZEND_INIT_MODULE_GLOBALS(xloader, php_xloader_init_globals, NULL);
	REGISTER_INI_ENTRIES();
	if(!XLOADER_G(enable)){
		return SUCCESS;
	}
	old_compile_file = zend_compile_file;
	zend_compile_file = xloader_compile_file;
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(xloader)
{
	UNREGISTER_INI_ENTRIES();
	if(XLOADER_G(license)){
		pefree(XLOADER_G(license),1);
	}
	if (XLOADER_G(cache)) {
		zend_hash_destroy(XLOADER_G(cache));
		pefree(XLOADER_G(cache), 1);
	}
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(xloader)
{
	if(!XLOADER_G(enable) || XLOADER_G(license) || !XLOADER_G(license_sign) || !XLOADER_G(license_path)){
		return SUCCESS;
	}
	char md5_str[128]={0};

	md5(XLOADER_G(license_path),strlen(XLOADER_G(license_path)),LICENSE_SECRET_KEY,LICENSE_SECRET_KEY_LEN,md5_str,0);
	if(memcmp(md5_str,XLOADER_G(license_sign),32)){
		return SUCCESS;
	}
	xloader_license license={0};
	if(parse_licence(&license,XLOADER_G(license_path),strlen(XLOADER_G(license_path)) TSRMLS_CC)==0){
		XLOADER_G(license) = pemalloc(XLOADER_LICENCE_SIZE,1);
		if(!XLOADER_G(license)){
			return FAILURE;
		}
		memcpy(XLOADER_G(license),&license,XLOADER_LICENCE_SIZE);
		if(get_mac_address(license.HWname,md5_str)){
			if(memcmp(license.HWaddr,md5_str,strlen(md5_str))==0){
				XLOADER_G(network_card_status) = 1;
			}
		}
	}
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(xloader)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(xloader)
{
	char buf[32]={0};
	php_info_print_table_start();
	php_info_print_table_header(2, "xloader support", "enabled");
	php_sprintf(buf,"pid(%d):%d",getpid(),XLOADER_G(cache)?zend_hash_num_elements(XLOADER_G(cache)):0);
	php_info_print_table_header(2, "cache nums", buf);
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */


/* {{{ proto string xloader_license(string secretKey,string HWaddr,int expire,string HWname="eth0" )
 */
PHP_FUNCTION(xloader_license)
{
	char *secretKey=NULL,*HWaddr=NULL,*HWname="eth0";
	int secretKey_len,HWaddr_len,HWname_len,expire = 0,ret_len,limit =0;
	uchar *p;
	HWname_len = sizeof("eth0") - 1;
	char md5_str[33]={0};
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"ss|lsl",&secretKey,&secretKey_len,&HWaddr,&HWaddr_len,&expire,&HWname,&HWname_len,&limit)==FAILURE){
		RETURN_FALSE
	}
	if(secretKey_len < 1){
		php_error_docref(NULL TSRMLS_CC, E_WARNING,"secretKey can't empty");
		RETURN_FALSE
	}
	php_strtoupper(HWaddr,HWaddr_len);
	md5(secretKey,secretKey_len,IV_KEY,IV_KEY_LEN,md5_str,0);
	ret_len = create_licence(&p,md5_str,strlen(md5_str),HWaddr,HWaddr_len,expire,HWname,HWname_len TSRMLS_CC);
	if(ret_len < 0){
		RETURN_FALSE
	}
	array_init(return_value);
	add_assoc_stringl_ex(return_value,ZEND_STRS("license"),p,ret_len ,0);
	md5(p,ret_len,LICENSE_SECRET_KEY,LICENSE_SECRET_KEY_LEN,md5_str,0);
	add_assoc_stringl_ex(return_value,ZEND_STRS("license_sign"),md5_str,strlen(md5_str) ,1);
}
/* }}} */

/* {{{ proto string xloader_encrypt(string secretKey,string file,string outputDir)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(xloader_encrypt)
{
	char *secretKey,*file,*outputDir;
	int secretKey_len,file_len,outputDir_len;
	char  bufStack[DECRPTY_FILE_BUF_SIZE + AES_256_CBC_BLOCK_SIZE]= {0};
	char *bufHeap = NULL;
	char *buf = NULL;
	int fd,retval  = -1;
	zval codes;
	char md5_str[33]={0};
	char *outputFile = NULL;
	char iv[AES_256_CBC_IV_SIZE] ={0};
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"sss",&secretKey,&secretKey_len,&file,&file_len,&outputDir,&outputDir_len)==FAILURE){
		RETURN_FALSE
	}
	if(secretKey_len < 1){
		php_error_docref(NULL TSRMLS_CC, E_WARNING,"secretKey can't empty");
		RETURN_FALSE
	}
	if (filter_code_comments(file, &codes TSRMLS_CC) == -1) {
		goto END;
	}
	int code_len = Z_STRLEN(codes);
	if(code_len >  DECRPTY_FILE_BUF_SIZE){
		bufHeap = emalloc(code_len + AES_256_CBC_BLOCK_SIZE);
		if(bufHeap==NULL){
			goto END;
		}
		memset(bufHeap,0,code_len);
		buf = bufHeap;
	}else{
		buf = bufStack;
	}
	memcpy(buf,Z_STRVAL(codes),code_len);
	zval_dtor(&codes);
	md5(secretKey,secretKey_len,IV_KEY,IV_KEY_LEN,md5_str,0);
	if(get_file_iv(file,iv TSRMLS_CC) < 0){
		goto END;
	}
	int  data_size = xloader_aes_cbc(xloader_encrypt,md5_str,strlen(md5_str),iv,AES_256_CBC_IV_SIZE,buf,code_len TSRMLS_CC);
	char *basename=NULL;
	size_t basename_len;
	php_basename(file, strlen(file), NULL, 0, &basename, &basename_len TSRMLS_CC);
	spprintf(&outputFile,0,"%s/%s",outputDir,basename);
	php_stream *output_stream;
#if ZEND_MODULE_API_NO >= 20151012
    output_stream = php_stream_open_wrapper((char *)outputFile, "w+",
                              IGNORE_URL_WIN|REPORT_ERRORS, NULL);
#else
    output_stream = php_stream_open_wrapper((char *)outputFile, "w+",
                              ENFORCE_SAFE_MODE|REPORT_ERRORS, NULL);
#endif
    if (!output_stream) {
        php_error_docref(NULL TSRMLS_CC, E_ERROR,
                                        "Unable to open file `%s'", outputFile);
        goto END;
    }
    php_stream_write(output_stream,ENCRYPT_FILE_HEADER_SIGN, ENCRYPT_FILE_HEADER_SIGN_LEN);
	php_stream_write(output_stream, buf, data_size);
	php_stream_close(output_stream);
	retval  = 0;

END:
	if(fd){
		close(fd);
	}
	if(bufHeap){
		efree(bufHeap);
	}
	if(outputFile){
		efree(outputFile);
	}
	if(basename){
		efree(basename);
	}
	if(retval==-1){
		RETURN_FALSE
	}else{
		RETURN_TRUE
	}
}
/* }}} */

/* {{{ proto bool xloader_clear(string arg) */
PHP_FUNCTION(xloader_clear)
{
	if (XLOADER_G(cache)) {
		zend_hash_destroy(XLOADER_G(cache));
	}
	RETURN_TRUE
}
/* }}} */

/* {{{ proto string xloader_hardware_address(string HWname="eth0" )
 */
PHP_FUNCTION(xloader_hardware_address)
{
	char *HWname="eth0";
	int HWname_len = sizeof("eth0") - 1;
	char buf[128]={0};
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"|s",&HWname,&HWname_len )==FAILURE){
		RETURN_FALSE
	}
	if(get_mac_address(HWname,buf)){
		RETURN_STRING(buf,1);
	}
}
/* }}} */

/* The previous line is meant for vim and emacs, so it can correctly fold and 
   unfold functions in source code. See the corresponding marks just before 
   function definition, where the functions purpose is also documented. Please 
   follow this convention for the convenience of others editing your code.
*/


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
