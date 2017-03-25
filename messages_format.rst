===============
Messages format
===============

This document details the message format for audisp-graylog, and lists the possible
messages.

How, Why, What
--------------

kernel side and rules loading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The Linux kernel sends messages via the netlink protocol to a user space
daemon, auditd.  These messages depends on the audit configuration, which is
generally saved in /etc/audit/audit.rules.  The rules are loaded at audit
startup into the kernel and define which system calls should be logged and
under which conditions.
Some other kernel components, such as AVC, may also emit non-syscall related messages.

audisp plugins
~~~~~~~~~~~~~~
The messages that auditd receives are then passed to audispd which is a
multiplexer, sending back those messages to various plugins.
Audisp-graylog is one of the plugins.

As audisp-graylog receives several syscall messages for a single event (like "write
to a file" or "execute a program"), it correlates on the message info, id and
aggregates all relevant information for a single event into a single message.

That message is then transformed to JSON format with a type, such as "EXECVE" or
"WRITE" and send to syslog.

Format example
--------------

.. note::

        Values such as "mode": "(null)" are omitted by audisp-graylog to reduce the message size.
        Only fields with actual values are sent/displayed.

.. note::

        All "audit" field values are string in order to deal with document indexing issues when the type changes
        between int and str for example (instead it's always str).

.. code::

    {
        "audit_category": "EXECVE",
        "audit_summary": "Execve: sudo cat /etc/passwd",
        "audit_hostname": "blah.private.scl3.mozilla.com",
        "audit_timestamp": "2014-03-18T23:20:31.013344+00:00"
        "audit_plugin": "audisp-graylog",
        "audit_version": "1.0.0",
        "audit": {
            "serial": "2939394",
            "uid": "0",
            "gid": "0",
            "euid": "0",
            "fsuid": "0",
            "egid": "0",
            "suid": "0",
            "sessionid": "20239",
            "ppid": "29929",
            "cwd": "/home/kang",
            "username": "root",
            "auditedusername": "kang",
            "auid": "1000",
            "inode": "283892",
            "parentprocess": "sudo",
            "process": "/bin/cat",
            "auditkey": "exe",
            "tty": "/dev/pts/0"
        },
    }

Fields reference
----------------
.. note:: Integer fields are of type uint32_t (i.e. bigger than regular signed int) even when stored as str. This means 4,294,967,295 is a valid value and does not represent -2,147,483,648.

.. note:: See also 'man 8 auditctl' and/or https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sec-Understanding_Audit_Log_Files.html

:audit_category: Type of message (such as execve, write, chmod, etc.).
:audit_summary: Human readable summary of the message.
:audit_hostname: System FQDN as seen get gethostbyname().
:audit_timestamp: UTC timestamp, or with timezone set.
:audit_plugin: Audit plugin name (audisp-graylog).
:audit_version: Audit plugin version.
:audit.serial: The message/event serial sent by audit. This is mainly used for debugging or as a reference between the Mozdef/JSON message and the host's original message.
:audit.uid,gid: User/group id who started the program.
:audit.username: Human readable alias of the uid.
:audit.euid: Effective user/group id the program is running as.
:audit.fsuid,fsgid: User/group id of the owner of the running program itself, on the filesystem.
:audit.ouid,ouid: Owner user/group id on the filesystem.
:audit.suid,sgid: Saved user/group id - used when changing uid sets within the program, but a uid/gid has been saved (i.e. the program can revert to the suid if it wants to).
:audit.auid or audit.originaluid: Auditd user id - the original user who logged in (always the same even after setuid - this is generally set by PAM).
:audit.originaluser: Human readable alias of the auid/originaluid.
:audit.rdev: Recorded device identifier (MAJOR:MINOR numbers).
:audit.rdev: Recorded device identifier for special files.
:audit.mode: File mode on the filesystem (full numeral mode, such as 0100600 - that would be 0600 "short mode" or u+rw or -rw------).
:audit.sessionid: Kernel session identifier for the user running the program. It's set at login.
:audit.tty: If any TTY is attached, it's there - used by interactive shells usually (such as /dev/pts/0).
:audit.auditkey: Custom identifier set by the person setting audit rules on the system.
:audit.process: Program involved's full path.
:audit.pid: PID of the program involved.
:audit.inode: Node identifier on the filesystem for the program.
:audit.cwd: Current working directory of the program.
:audit.parentprocess: Name of the parent process which has spawned audit.process.
:audit.ppid: PID of the parent process.

Implemented message categories
------------------------------

:WRITE: writes to a file, 'w' in audit.rules.
:ATTR: change file attributes/metadata, 'a' in audit.rules.
:CHMOD: change file mode, 'chmod' syscall in audit.rules.
:CHOWN: change file owner, 'chown' syscall in audit.rules.
:PTRACE: process trace, gdb/strace do that for example, 'ptrace' syscall in audit.rules.
:EXECVE: execute program, 'execve' syscall in audit.rules.
:AVC_APPARMOR: AppArmor messages, generally used on Ubuntu. Not handled by audit.rules.
:ANOM_PROMISCUOUS: network interface promiscuous setting on/off. Handled by 'ioctl' syscall in audit.rules.
