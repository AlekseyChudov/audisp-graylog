==========
audisp-graylog
==========

.. contents:: Table of contents

This program is a plugin for Linux Audit user space programs available at <http://people.redhat.com/sgrubb/audit/>.
It uses the audisp multiplexer.

Audisp-graylog correlates messages coming from the kernel's audit (and through audisp) into a single JSON message that is
sent to syslog.

Building
--------

Required dependencies: audit-libs-devel, libtool

For package building: rpmbuild, FPM

Build targets:
=============
They're self explanatory.

- make
- make rpm
- make deb
- make install
- make uninstall
- make clean

Static compilation tips
=======================
If you need to compile in statically compiled libraries, here are the variables to change from the makefile.

 ::

    @@ -48,9 +48,11 @@ else ifeq ($(DEBUG),1)
    else
    CFLAGS  := -fPIE -DPIE -g -O2 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2
    endif
    +CFLAGS := -g -O2 -D_REENTRANT -D_GNU_SOURCE -fstack-protector-all -D_FORTIFY_SOURCE=2

    -LDFLAGS        := -pie -Wl,-z,relro
    -LIBS   := -lauparse -laudit
    +#LDFLAGS       := -pie -Wl,-z,relro -static
    +LDFLAGS := -static -ldl -lz -lrt
    +LIBS   := -lauparse -laudit
    DEFINES        := -DPROGRAM_VERSION\=${VERSION} ${REORDER_HACKF} ${IGNORE_EMPTY_EXECVE_COMMANDF}

    GCC            := gcc

How to forward messages to Graylog Server
--------------------------------------------------------------

Example for rsyslog
===================

 ::

    if $programname == 'audisp-graylog' then {
        *.* @graylog.example.com:5514;RSYSLOG_SyslogProtocol23Format
        stop
    }

Deal with auditd quirks
--------------------------------------------------------------

These examples filter out messages that may clutter your log or/and DOS yourself (high I/O) if auditd goes
down for any reason.

Example for rsyslog
===================

 ::

    #Drop native audit messages from the kernel (may happen is auditd dies, and may kill the system otherwise)
    :msg, regex, "type=[0-9]* audit" ~
    #Drop audit sid msg (work-around until RH fixes the kernel - should be fixed in RHEL7 and recent RHEL6)
    :msg, contains, "error converting sid to string" ~

Example for syslog-ng
=====================

 ::

    source s_syslog { unix-dgram("/dev/log"); };
    filter f_not_auditd { not message("type=[0-9]* audit") or not message("error converting sid to string"); };
    log{ source(s_syslog);f ilter(f_not_auditd); destination(d_logserver); };

Misc other things to do
=======================

- It is suggested to bump the audispd queue to adjust for extremely busy systems, for ex. q_depth=512.
- You will also probably need to bump the kernel-side buffer and change the rate limit in audit.rules, for ex. -b 16384
  -r 500.

Message handling
----------------

Syscalls are interpreted by audisp-graylog and transformed into a JSON message.
This means, for example, all execve() and related calls will be aggregated into a message of type EXECVE.

Supported messages are listed in the document messages_format.rst

Graylog Server Extractor configuration
--------------------------------------

.. image:: https://raw.githubusercontent.com/AlekseyChudov/audisp-graylog/master/images/audisp-graylog-extractor.png
