#
# File		: Makefile
# Description	: Build file for nltpmd
# Created	: Thu Dec 12 09:34:51 PST 2013
# By		: Dave Tian
#

#
# Environment Setup

LIBDIRS=
DEPFILE=Makefile.dep
CC=gcc
CFLAGS=-c $(INCLUDES) -g -Wall 
LINK=gcc
LINKFLAGS=-g
LIBS=-lgcrypt -ltspi

#
# Setup builds

TPMDOBJS= nltpmd.o \
	tpmw.o \
	nlm.o

TARGETS	= nltpmd

#
# Project Builds

nltpmd : $(TPMDOBJS)
	$(LINK) $(LINKFLAGS) $(TPMDOBJS) $(LIBS) -o $@

# Various maintenance stuff
clean : 
	rm -f $(TARGETS) $(TPMDOBJS) $(DEPFILE) 2>&1

install:
	install -C $(TPMDOBJS) $(TARGETDIR)


# Do dependency generation
depend : $(DEPFILE)

$(DEPFILE) : $(TPMDOBJS:.o=.c)
	gcc -MM $(CFLAGS) $(TPMDOBJS:.o=.c) > $(DEPFILE)

