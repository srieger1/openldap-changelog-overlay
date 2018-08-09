# Copyright 2010 Sebastian Rieger All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

LIBTOOL=../../../libtool
OPT=-g -O2
CC=gcc

DEFS=-DSLAPD_OVER_CHANGELOG=SLAPD_MOD_DYNAMIC
INCS=-I../../../include -I../../../servers/slapd
LIBS=-lldap_r -llber

INSTALLPATH=/usr/local/libexec/openldap

all:	changelog.la


changelog.lo:	changelog.c
	$(LIBTOOL) --mode=compile $(CC) $(OPT) $(DEFS) $(INCS) -c $?


changelog.la:	changelog.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info 0:0:0 \
	-rpath $(INSTALLPATH) -module -o $@ $? $(LIBS)

clean:
	rm -f changelog.o
	rm -f changelog.la
	rm -f changelog.lo
	rm -rf .libs

install:
	$(LIBTOOL) --mode=install install -c changelog.la $(INSTALLPATH)/changelog.la
	$(LIBTOOL) --mode=finish $(INSTALLPATH)
