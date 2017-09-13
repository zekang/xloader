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

#ifndef PHP_XLOADER_H
#define PHP_XLOADER_H

extern zend_module_entry xloader_module_entry;
#define phpext_xloader_ptr &xloader_module_entry

#define PHP_XLOADER_VERSION "0.1.0"

#ifdef PHP_WIN32
#	define PHP_XLOADER_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_XLOADER_API __attribute__ ((visibility("default")))
#else
#	define PHP_XLOADER_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(xloader);
PHP_MSHUTDOWN_FUNCTION(xloader);
PHP_RINIT_FUNCTION(xloader);
PHP_RSHUTDOWN_FUNCTION(xloader);
PHP_MINFO_FUNCTION(xloader);

PHP_FUNCTION(xloader_license);
PHP_FUNCTION(xloader_encrypt);
PHP_FUNCTION(xloader_clear);
PHP_FUNCTION(xloader_hardware_address);

typedef unsigned char uchar;

#define USER_SECRET_KEY_LEN  32
#define USER_HWADDR_LEN 32
#define USER_HWNAME_LEN 16
#define USER_TOKEN_LEN 16

typedef struct _license{
	char token[USER_TOKEN_LEN];
	char secretKey[USER_SECRET_KEY_LEN];
	char HWaddr[USER_HWADDR_LEN];
	char HWname[USER_HWNAME_LEN];
	int  expire;
	char extend[256-sizeof(int)-USER_SECRET_KEY_LEN-USER_HWADDR_LEN-USER_HWNAME_LEN - USER_TOKEN_LEN ];
}xloader_license;

#define XLOADER_LICENCE_SIZE sizeof(struct _license)

ZEND_BEGIN_MODULE_GLOBALS(xloader)
	zend_bool  			enable;
    zend_bool  			network_card_status;
    zend_bool  			cache_enable;
	int   				expire;
	HashTable*			cache;
	char*				license_path;
	char*				license_sign;
	xloader_license*	license;
ZEND_END_MODULE_GLOBALS(xloader)

/* In every utility function you add that needs to use variables 
   in php_xloader_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as XLOADER_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define XLOADER_G(v) TSRMG(xloader_globals_id, zend_xloader_globals *, v)
#else
#define XLOADER_G(v) (xloader_globals.v)
#endif

#endif	/* PHP_XLOADER_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
