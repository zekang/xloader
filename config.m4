dnl $Id$
dnl config.m4 for extension xloader

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(xloader, for xloader support,
dnl Make sure that the comment is aligned:
dnl [  --with-xloader             Include xloader support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(xloader, whether to enable xloader support,
Make sure that the comment is aligned:
[  --enable-xloader           Enable xloader support])

if test "$PHP_XLOADER" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-xloader -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/xloader.h"  # you most likely want to change this
  dnl if test -r $PHP_XLOADER/$SEARCH_FOR; then # path given as parameter
  dnl   XLOADER_DIR=$PHP_XLOADER
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for xloader files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       XLOADER_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$XLOADER_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the xloader distribution])
  dnl fi

  dnl # --with-xloader -> add include path
  dnl PHP_ADD_INCLUDE($XLOADER_DIR/include)

  dnl # --with-xloader -> check for lib and symbol presence
  dnl LIBNAME=xloader # you may want to change this
  dnl LIBSYMBOL=xloader # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $XLOADER_DIR/$PHP_LIBDIR, XLOADER_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_XLOADERLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong xloader lib version or lib not found])
  dnl ],[
  dnl   -L$XLOADER_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(XLOADER_SHARED_LIBADD)

  PHP_NEW_EXTENSION(xloader, xloader.c aes.c, $ext_shared)
fi
