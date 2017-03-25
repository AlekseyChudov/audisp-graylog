# Copyright (c) 2014 Mozilla Corporation.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Guillaume Destuynder <gdestuynder@mozilla.com>
#   Aleksey Chudov <aleksey.chudov@gmail.com>

VERSION	:= 1.0.0

#FPM options, suggestions:
# --replaces audisp-cef
# --rpm-digest sha512 --rpm-sign
FPMOPTS :=

# Turn this on if you get issues with out of sequence messages/missing event attributes
# Only needed for some versions of libaudit - if you don't have problems, leave off.
REORDER_HACK :=
ifeq ($(REORDER_HACK),1)
	REORDER_HACKF	:= -DREORDER_HACK
endif

# Turn this off if you want the extra noise of script execs and the like, which do not produce an EXECVE audit message
# See the source code for more info.
IGNORE_EMPTY_EXECVE_COMMAND := 1
ifneq ($(IGNORE_EMPTY_EXECVE_COMMAND),0)
	IGNORE_EMPTY_EXECVE_COMMANDF	:= -DIGNORE_EMPTY_EXECVE_COMMAND
endif

DEBUG	:=
ifeq ($(DEBUG),2)
	DEBUGF	:= -DDEBUG
	CFLAGS	:= -Wall -fPIE -DPIE -g -O0 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all
else ifeq ($(DEBUG),1)
	CFLAGS	:= -fPIE -DPIE -g -O0 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all
else
	CFLAGS	:= -fPIE -DPIE -g -O2 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2
endif

LDFLAGS	:= -pie -Wl,-z,relro
LIBS	:= -lauparse -laudit
DEFINES	:= -DPROGRAM_VERSION\=${VERSION} ${REORDER_HACKF} ${IGNORE_EMPTY_EXECVE_COMMANDF}

GCC		:= gcc
LIBTOOL	:= libtool
INSTALL	:= install

DESTDIR	:= /
PREFIX	:= /usr

all: audisp-graylog

audisp-graylog: audisp-graylog.o
	${LIBTOOL} --tag=CC --mode=link gcc ${CFLAGS} ${LDFLAGS} ${LIBS} -o audisp-graylog audisp-graylog.o

audisp-graylog.o: audisp-graylog.c
	${GCC} -I. ${CFLAGS} ${DEBUGF} ${LIBS} ${DEFINES} -c -o audisp-graylog.o audisp-graylog.c

install: audisp-graylog graylog.conf
	${INSTALL} -D -m 0755 audisp-graylog ${DESTDIR}/${PREFIX}/sbin/audisp-graylog
	${INSTALL} -D -m 0644 graylog.conf ${DESTDIR}/${PREFIX}/etc/audisp/plugins.d/graylog.conf

uninstall:
	rm -f ${DESTDIR}/${PREFIX}/sbin/audisp-graylog
	rm -f ${DESTDIR}/${PREFIX}/etc/audisp/plugins.d/graylog.conf

packaging: audisp-graylog graylog.conf
	${INSTALL} -D -m 0755 audisp-graylog tmp/sbin/audisp-graylog
	${INSTALL} -D -m 0644 graylog.conf tmp/etc/audisp/plugins.d/graylog.conf

rpm: packaging
	fpm ${FPMOPTS} -C tmp -v ${VERSION} -n audisp-graylog --license GPL --description "Graylog plugin for Auditd" \
		--url https://github.com/AlekseyChudov/audisp-graylog -d audit-libs \
		--config-files etc/audisp/plugins.d/graylog.conf -s dir -t rpm .

deb: packaging
	fpm ${FPMOPTS} -C tmp -v ${VERSION} -n audisp-graylog --license GPL --description "Graylog plugin for Auditd" \
		--url https://github.com/AlekseyChudov/audisp-graylog -d auditd --deb-build-depends libaudit-dev \
		--config-files etc/audisp/plugins.d/graylog.conf -s dir -t deb .

clean:
	rm -f audisp-graylog
	rm -fr *.o
	rm -fr tmp
	rm -rf *.rpm
	rm -rf *.deb

.PHONY: clean
