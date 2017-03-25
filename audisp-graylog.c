/* vim: ts=4:sw=4:noexpandtab
 * audisp-graylog.c --
 * Copyright (c) 2014 Mozilla Corporation.
 * Portions Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Guillaume Destuynder <gdestuynder@mozilla.com>
 *   Steve Grubb <sgrubb@redhat.com>
 *   Aleksey Chudov <aleksey.chudov@gmail.com>
 *
 */

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <netdb.h>
#include "libaudit.h"
#include "auparse.h"

#define MAX_JSON_MSG_SIZE 4096
#define MAX_ARG_LEN 2048
#define MAX_SUMMARY_LEN 256
#define TS_LEN 64
#define MAX_ATTR_SIZE MAX_AUDIT_MESSAGE_LENGTH
#ifdef REORDER_HACK
#define NR_LINES_BUFFERED 64
#endif

#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "1"
#endif
#ifndef PROGRAM_NAME
#define PROGRAM_NAME "audisp-graylog"
#endif
#define _STR(x) #x
#define STR(x) _STR(x)

extern int h_errno;

static volatile int sig_stop = 0;
static char *hostname = NULL;
static auparse_state_t *au = NULL;
static int machine = -1;

typedef struct { char *val; } msg_t;

/* msg attributes list */
typedef struct	ll {
	char value[MAX_ATTR_SIZE];
	struct ll *next;
} attr_t;

struct json_msg_type {
	char	*category;
	char	*summary;
	char	*hostname;
	char	*timestamp;
	struct	ll *details;
};

/* msgs to send queue/buffer */
typedef struct lq {
	char msg[MAX_JSON_MSG_SIZE];
	struct lq *next;
} queue_t;

struct lq *msg_queue_list;
unsigned int msg_queue_list_size = 0;

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

static void int_handler(int sig)
{
	if (sig_stop == 1) {
		fprintf(stderr, "Repeated keyboard interrupt signal, forcing unclean program termination.\n");
		exit(127);
	}
	sig_stop = 1;
}

static void term_handler(int sig)
{
	sig_stop = 1;
}

#ifdef REORDER_HACK
/*
 * Hack to reorder input
 * libaudit's auparse seems not to correlate messages correctly if event ids are out of sequence, ex (event id are
 * 418143181 and 418143182):
 * type=EXECVE msg=audit(1418253698.016:418143181): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=EXECVE msg=audit(1418253698.016:418143182): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=CWD msg=audit(1418253698.016:418143181):  cwd="/opt/observium"
 * type=CWD msg=audit(1418253698.016:418143182):  cwd="/opt/observium"
 *
 * This hack sort them back so that event ids are back to back like this:
 * type=EXECVE msg=audit(1418253698.016:418143181): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=CWD msg=audit(1418253698.016:418143181):  cwd="/opt/observium"
 * type=EXECVE msg=audit(1418253698.016:418143182): argc=3 a0="sh" a1="-c" a2=[redacted]
 * type=CWD msg=audit(1418253698.016:418143182):  cwd="/opt/observium"
 *
 * Without the hack, when the event id correlation fails, auparse would only return the parsed event until the point of
 * failure (so basically half of the message will be missing from the event/fields will be empty...)
 *
 * WARNING: The hack relies on properly null terminated strings here and there and doesn't do much bound checking other
 * than that. Be careful.
 * NOTE: This hack is only necessary when you can't fix libaudit easily, obviously. It's neither nice neither all that fast.
 */

/* count occurences of c in *in */
unsigned int strcharc(char *in, char c)
{
	unsigned int i = 0;

	for (i = 0; in[i]; in[i] == c ? i++ : *in++);
	return i;
}

static int eventcmp(const void *p1, const void *p2)
{
	char *s1, *s2;
	char *a1, *a2;
	int i;
	s1 = *(char * const*)p1;
	s2 = *(char * const*)p2;

	if (!s1 || !s2)
		return 0;

	a1 = s1;
	i = 0;
	while (a1[0] != ':' && a1[0] != '\0' && i < MAX_AUDIT_MESSAGE_LENGTH) {
		i++;
		a1++;
	}

	a2 = s2;
	i = 0;
	while (a2[0] != ':' && a2[0] != '\0' && i < MAX_AUDIT_MESSAGE_LENGTH) {
		i++;
		a2++;
	}

	return strcmp(a1, a2);
}

size_t reorder_input_hack(char **sorted_tmp, char *tmp)
{
		unsigned int lines = 0;
		unsigned int llen = 0;
		size_t flen = 0;
		unsigned int i = 0;
		lines = strcharc(tmp, '\n');

		char *buf[lines];
		char *line;
		char *saved;

		line = strtok_r(tmp, "\n", &saved);
		if (!line) {
			syslog(LOG_ERR, "message has no LF, message lost!");
			return 0;
		}

		llen = strnlen(line, MAX_AUDIT_MESSAGE_LENGTH);
		buf[i] = malloc(llen + 1);
		if (!buf[i]) {
			*sorted_tmp = tmp;
			syslog(LOG_ERR, "reorder_input_hack() malloc failed won't reorder");
			return strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH);
		}
		snprintf(buf[i], llen+1, "%s", line);
		i++;

		for (i; i < lines; i++) {
			line = strtok_r(NULL, "\n", &saved);
			if (!line) {
				continue;
			}
			llen = strnlen(line, MAX_AUDIT_MESSAGE_LENGTH);
			buf[i] = malloc(llen + 1);
			if (!buf[i]) {
				syslog(LOG_ERR, "reorder_input_hack() malloc failed partially reordering");
				continue;
			}
			snprintf(buf[i], llen+1, "%s", line);
		}

		qsort(&buf, lines, sizeof(char *), eventcmp);

		for (i = 0; i < lines; i++) {
			flen += snprintf(*sorted_tmp+flen, MAX_AUDIT_MESSAGE_LENGTH, "%s\n",  buf[i]);
			if (buf[i]) {
				free(buf[i]);
			}
		}
		return flen;
}
#endif

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH];
	int len=0;
	struct sigaction sa;
	struct hostent *ht;
	char nodename[64];

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return 1;
	sa.sa_handler = int_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return 1;

	openlog(PROGRAM_NAME, LOG_CONS, LOG_AUTHPRIV);

	if (gethostname(nodename, sizeof(nodename)-1)) {
		snprintf(nodename, 10, "localhost");
	}
	nodename[sizeof(nodename)] = '\0';
	ht = gethostbyname(nodename);
	if (ht == NULL) {
		hostname = strdup("localhost");
		if (hostname == NULL)
			return 1;
		syslog(LOG_ALERT,
			"gethostbyname could not find machine hostname, please fix this. Using %s as fallback. Error: %s",
			hostname, hstrerror(h_errno));
	} else {
		hostname = strdup(ht->h_name);
		if (hostname == NULL)
			return 1;
	}

	au = auparse_init(AUSOURCE_FEED, NULL);
	if (au == NULL) {
		syslog(LOG_ERR, "could not initialize auparse");
		return -1;
	}

	machine = audit_detect_machine();
	if (machine < 0) {
		return -1;
	}

#ifdef REORDER_HACK
	int start = 0;
	int stop = 0;
	int i = 0;
	char *full_str_tmp = malloc(NR_LINES_BUFFERED*MAX_AUDIT_MESSAGE_LENGTH);
	char *sorted_tmp = malloc(NR_LINES_BUFFERED*MAX_AUDIT_MESSAGE_LENGTH);
	if (!sorted_tmp || !full_str_tmp) {
		syslog(LOG_ERR, "main() malloc failed for sorted_tmp || full_str_tmp, this is fatal");
		return -1;
	}
	sorted_tmp[0] = '\0';
	full_str_tmp[0] = '\0';
#endif

	auparse_add_callback(au, handle_event, NULL, NULL);
	syslog(LOG_INFO, "%s loaded\n", PROGRAM_NAME);

	/* At this point we're initialized so we'll read stdin until closed and feed the data to auparse, which in turn will
	 * call our callback (handle_event) every time it finds a new complete message to parse.
	 */
	do {
		/* NOTE: There's quite a few reasons for auparse_feed() from libaudit to fail parsing silently so we have to be careful here.
		 * Anything passed to it:
		 * - must have the same timestamp for a given event id. (kernel takes care of that, if not, you're out of luck).
		 * - must always be LF+NULL terminated ("\n\0"). (fgets takes care of that even thus it's not nearly as fast as fread).
		 * - must always have event ids in sequential order. (REORDER_HACK takes care of that, it also buffer lines, since, well, it needs to).
		 */
		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin)) {
			if (sig_stop)
				break;

			len = strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH);
#ifdef REORDER_HACK
			if (strncmp(tmp, "type=EOE", 8) == 0) {
				stop++;
			} else if (strncmp(tmp, "type=SYSCALL", 12) == 0) {
				start++;
			}
			if (i > NR_LINES_BUFFERED || start != stop) {
				strncat(full_str_tmp, tmp, len);
				i++;
			} else {
				strncat(full_str_tmp, tmp, len);
				len = reorder_input_hack(&sorted_tmp, full_str_tmp);
				auparse_feed(au, sorted_tmp, len);
				i = 0;
				start = stop = 0;
				sorted_tmp[0] = '\0';
				full_str_tmp[0] = '\0';
			}
#else
			auparse_feed(au, tmp, len);
#endif
		}

		if (feof(stdin))
			break;
	} while (sig_stop == 0);

	auparse_flush_feed(au);
	auparse_destroy(au);
	free(hostname);
#ifdef REORDER_HACK
	free(sorted_tmp);
#endif
	syslog(LOG_INFO, "%s unloaded\n", PROGRAM_NAME);
	closelog();

	return 0;
}

/*
 * This function seeks to the specified record returning its type on succees
 */
static int goto_record_type(auparse_state_t *au, int type)
{
	int cur_type;

	auparse_first_record(au);
	do {
		cur_type = auparse_get_type(au);
		if (cur_type == type) {
			auparse_first_field(au);
			return type;  // Normal exit
		}
	} while (auparse_next_record(au) > 0);

	return -1;
}

/* Removes quotes
 * Remove  CR and LF
 * @const char *in: if NULL, no processing is done.
 */
char *unescape(const char *in)
{
	if (in == NULL)
		return NULL;

	char *dst = (char *)in;
	char *s = dst;
	char *src = (char *)in;
	char c;

	while ((c = *src++) != '\0') {
		if ((c == '"') || (c == '\n') || (c == '\r') || (c == '\t')
				|| (c == '\b') || (c == '\f') || (c == '\\'))
			continue;
		*dst++ = c;
	}
	*dst++ = '\0';
	return s;
}

/* Add a field to the json msg's details={}
 * @attr_t *list: the attribute list to extend
 * @const char *st: the attribute name to add
 * @const char *val: the attribut value - if NULL, we won't add the field to the json message at all.
 */
attr_t *_json_add_attr(attr_t *list, const char *st, char *val, int freeme)
{
	attr_t *new;

	if (st == NULL || !strncmp(st, "(null)", 6) || val == NULL || !strncmp(val, "(null)", 6)) {
		return list;
	}

	new = malloc(sizeof(attr_t));
	if (!new) {
		syslog(LOG_ERR, "json_add_attr() malloc failed attribute will be empty: %s", st);
		return list;
	}
	snprintf(new->value, MAX_ATTR_SIZE, "\"%s\":\"%s\"", st, unescape(val));
	new->next = list;

	if (freeme) {
		free(val);
	}

	return new;
}

/* Convenience wrappers for _json_add_attr */
attr_t *json_add_attr_free(attr_t *list, const char *st, char *val)
{
	return _json_add_attr(list, st, val, 1);
}

attr_t *json_add_attr(attr_t *list, const char *st, const char *val)
{
	return _json_add_attr(list, st, (char *)val, 0);
}

void json_del_attrs(attr_t *head)
{
	attr_t *prev;
	while (head) {
		prev = head;
		head = head->next;
		free(prev);
	}
}

/* Resolve uid to username - returns malloc'd value */
char *get_username(int uid)
{
	size_t bufsize;
	char *buf;
	char *name;
	struct passwd pwd;
	struct passwd *result;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 16384;
	buf = (char *)alloca(bufsize);
	if (!buf) {
		return NULL;
	}

	if (uid == -1) {
		return NULL;
	}
	if (getpwuid_r(uid, &pwd, buf, bufsize, &result) != 0) {
		return NULL;
	}
	if (result == NULL) {
		return NULL;
	}
	name = strdup(pwd.pw_name);
	return name;
}

/* Resolve process name from pid */
char *get_proc_name(int pid)
{
	char p[1024];
	int ret;
	static char proc[64];
	FILE *fp;
	snprintf(p, 512, "/proc/%d/status", pid);
	fp = fopen(p, "r");
	if (fp) {
		ret = fscanf(fp, "Name: %63s", proc);
		fclose(fp);
	} else
		return NULL;

	if (ret == 0)
		return NULL;

	return proc;
}

/* This creates the JSON message we'll send over by deserializing the C struct into a char array
 * the function name is rather historical, since this does not send to syslog anymore.
 */
void syslog_json_msg(struct json_msg_type json_msg)
{
	attr_t *head = json_msg.details;
	attr_t *prev;
	char msg[MAX_JSON_MSG_SIZE];
	int len;

	len = snprintf(msg, MAX_JSON_MSG_SIZE,
"{\"audit_category\":\"%s\",\"audit_summary\":\"%s\",\"audit_hostname\":\"%s\",\
\"audit_timestamp\":\"%s\",\"audit_plugin\":\"%s\",\"audit_version\":\"%s\",\
\"audit\":{",
		json_msg.category, json_msg.summary, json_msg.hostname,
		json_msg.timestamp, PROGRAM_NAME, STR(PROGRAM_VERSION));

	while (head) {
		len += snprintf(msg+len, MAX_JSON_MSG_SIZE-len, "%s,", head->value);
		prev = head;
		head = head->next;
		free(prev);
		if (head == NULL)
		    len--;
	}
	len += snprintf(msg+len, MAX_JSON_MSG_SIZE-len, "}}");
	msg[MAX_JSON_MSG_SIZE-1] = '\0';

	syslog(LOG_INFO, "%s", msg);
}

/* The main event handling, parsing function */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, num=0;


	struct json_msg_type json_msg = {
		.category	= NULL,
		.summary	= NULL,
		.hostname	= hostname,
		.timestamp	= NULL,
		.details	= NULL,
	};

	typedef enum {
		CAT_EXECVE,
		CAT_WRITE,
		CAT_PTRACE,
		CAT_ATTR,
		CAT_APPARMOR,
		CAT_CHMOD,
		CAT_CHOWN,
		CAT_PROMISC,
		CAT_TIME
	} category_t;
	category_t category;

	const char *cwd = NULL, *argc = NULL, *cmd = NULL;
	const char *path = NULL;
	const char *dev = NULL;
	const char *sys;
	const char *syscall = NULL;
	char fullcmd[MAX_ARG_LEN+1] = "\0";
	char serial[64] = "\0";
	time_t t;
	struct tm *tmp;

	char f[8];
	int len, tmplen;
	int argcount, i;
	int promisc;
	int havejson = 0;

	/* wait until the lib gives up a full/ready event */
	if (cb_event_type != AUPARSE_CB_EVENT_READY) {
		return;
	}

	json_msg.timestamp = (char *)alloca(TS_LEN);
	json_msg.summary = (char *)alloca(MAX_SUMMARY_LEN);
	if (!json_msg.summary || !json_msg.timestamp) {
		syslog(LOG_ERR, "handle_event() alloca failed, message lost!");
		return;
	}

	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		if (!type)
			continue;

		if (!auparse_first_field(au))
			continue;

		t = auparse_get_time(au);
		tmp = localtime(&t);
		strftime(json_msg.timestamp, TS_LEN, "%FT%T%z", tmp);
		snprintf(serial, TS_LEN-1, "%lu", auparse_get_serial(au));
		json_msg.details = json_add_attr(json_msg.details, "serial", serial);

		switch (type) {
			case AUDIT_ANOM_PROMISCUOUS:
				dev = auparse_find_field(au, "dev");
				if (!dev) {
					json_del_attrs(json_msg.details);
					return;
				}

				havejson = 1;
				category = CAT_PROMISC;

				json_msg.details = json_add_attr(json_msg.details, "dev", dev);
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "promiscious", auparse_find_field(au, "prom"));
				promisc = auparse_get_field_int(au);
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "old_promicious", auparse_find_field(au, "old_prom"));
				goto_record_type(au, type);
				if (auparse_find_field(au, "auid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "originaluser",
														get_username(auparse_get_field_int(au)));

					json_msg.details = json_add_attr(json_msg.details, "originaluid",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "user", get_username(auparse_get_field_int(au)));
					json_msg.details = json_add_attr(json_msg.details, "uid", auparse_get_field_str(au));
				}
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "gid", auparse_find_field(au, "gid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "session", auparse_find_field(au, "ses"));
				goto_record_type(au, type);
				break;

			case AUDIT_AVC:
				argc = auparse_find_field(au, "apparmor");
				if (!argc) {
					json_del_attrs(json_msg.details);
					return;
				}

				havejson = 1;
				category = CAT_APPARMOR;

				json_msg.details = json_add_attr(json_msg.details, "aaresult", auparse_get_field_str(au));
				goto_record_type(au, type);

				json_msg.summary = unescape(auparse_find_field(au, "info"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aacoperation", auparse_find_field(au, "operation"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aaprofile", auparse_find_field(au, "profile"));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aacommand", auparse_find_field(au, "comm"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "parent"))
					json_msg.details = json_add_attr(json_msg.details, "parentprocess",
														get_proc_name(auparse_get_field_int(au)));

				goto_record_type(au, type);

				if (auparse_find_field(au, "pid"))
					json_msg.details = json_add_attr(json_msg.details, "processname",
														get_proc_name(auparse_get_field_int(au)));
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "aaerror", auparse_find_field(au, "error"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "aaname", auparse_find_field(au, "name"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "aasrcname", auparse_find_field(au, "srcname"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "aaflags", auparse_find_field(au, "flags"));
				goto_record_type(au, type);
				break;

			case AUDIT_EXECVE:
				argc = auparse_find_field(au, "argc");
				if (argc)
					argcount = auparse_get_field_int(au);
				else
					argcount = 0;
				fullcmd[0] = '\0';
				len = 0;
				for (i = 0; i != argcount; i++) {
					goto_record_type(au, type);
					tmplen = snprintf(f, 7, "a%d", i);
					f[tmplen] = '\0';
					cmd = auparse_find_field(au, f);
					cmd = auparse_interpret_field(au);
					if (!cmd)
						continue;
					if (MAX_ARG_LEN-strlen(fullcmd) > strlen(cmd)) {
						if (len == 0)
							len += sprintf(fullcmd+len, "%s", cmd);
						else
							len += sprintf(fullcmd+len, " %s", cmd);
					}
				}
				json_msg.details = json_add_attr(json_msg.details, "command", fullcmd);
				break;

			case AUDIT_CWD:
				cwd = auparse_find_field(au, "cwd");
				if (cwd) {
					auparse_interpret_field(au);
					json_msg.details = json_add_attr(json_msg.details, "cwd", auparse_find_field(au, "cwd"));
				}
				break;

			case AUDIT_PATH:
				path = auparse_find_field(au, "name");
				json_msg.details = json_add_attr(json_msg.details, "path", path);
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "inode", auparse_find_field(au, "inode"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "dev", auparse_find_field(au, "dev"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "mode", auparse_find_field(au, "mode"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "ouid", auparse_find_field(au, "ouid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "ogid", auparse_find_field(au, "ogid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "rdev", auparse_find_field(au, "rdev"));
				goto_record_type(au, type);
				break;

			case AUDIT_SYSCALL:
				syscall = auparse_find_field(au, "syscall");
				if (!syscall) {
					json_del_attrs(json_msg.details);
					return;
				}
				i = auparse_get_field_int(au);
				sys = audit_syscall_to_name(i, machine);
				if (!sys) {
					syslog(LOG_DEBUG, "System call %u is not supported by %s", i, PROGRAM_NAME);
					json_del_attrs(json_msg.details);
					return;
				}

				json_msg.details = json_add_attr(json_msg.details, "processname", auparse_find_field(au, "comm"));
				goto_record_type(au, type);

				if (!strncmp(sys, "write", 5) || !strncmp(sys, "open", 4) || !strncmp(sys, "unlink", 6) || !strncmp(sys,
							"rename", 6)) {
					havejson = 1;
					category = CAT_WRITE;
				} else if (!strncmp(sys, "setxattr", 8)) {
					havejson = 1;
					category = CAT_ATTR;
				} else if (!strncmp(sys, "chmod", 5)) {
					havejson = 1;
					category = CAT_CHMOD;
				} else if (!strncmp(sys, "chown", 5) || !strncmp(sys, "fchown", 6)) {
					havejson = 1;
					category = CAT_CHOWN;
				} else if (!strncmp(sys, "ptrace",  6)) {
					havejson = 1;
					category = CAT_PTRACE;
				} else if (!strncmp(sys, "execve", 6)) {
					havejson = 1;
					category = CAT_EXECVE;
				} else if (!strncmp(sys, "ioctl", 5)) {
					category = CAT_PROMISC;
				} else if (!strncmp(sys, "adjtimex", 8)) {
					category = CAT_TIME;
				} else {
					syslog(LOG_INFO, "System call %u %s is not supported by %s", i, sys, PROGRAM_NAME);
				}

				json_msg.details = json_add_attr(json_msg.details, "auditkey", auparse_find_field(au, "key"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "ppid"))
					json_msg.details = json_add_attr(json_msg.details, "parentprocess",
														get_proc_name(auparse_get_field_int(au)));

				goto_record_type(au, type);

				if (auparse_find_field(au, "auid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "originaluser",
														get_username(auparse_get_field_int(au)));

					json_msg.details = json_add_attr(json_msg.details, "originaluid",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					json_msg.details = json_add_attr_free(json_msg.details, "user", get_username(auparse_get_field_int(au)));
					json_msg.details = json_add_attr(json_msg.details, "uid", auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				json_msg.details = json_add_attr(json_msg.details, "tty", auparse_find_field(au, "tty"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "process", auparse_find_field(au, "exe"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "ppid", auparse_find_field(au, "ppid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "pid", auparse_find_field(au, "pid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "gid", auparse_find_field(au, "gid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "euid", auparse_find_field(au, "euid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "suid", auparse_find_field(au, "suid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "fsuid", auparse_find_field(au, "fsuid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "egid", auparse_find_field(au, "egid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "sgid", auparse_find_field(au, "sgid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "fsgid", auparse_find_field(au, "fsgid"));
				goto_record_type(au, type);
				json_msg.details = json_add_attr(json_msg.details, "session", auparse_find_field(au, "ses"));
				goto_record_type(au, type);
				break;

			default:
				break;
		}
		num++;
	}

	if (!havejson) {
		json_del_attrs(json_msg.details);
		return;
	}

	/* We set the category/summary here as the JSON msg structure is complete at this point. (i.e. just before
	 * syslog_json_msg...) Since we don't know the order of messages, this is the only way to ensure we can fill a
	 * useful summary from various AUDIT messages (sometimes the values are set from AUDIT_EXECVE, sometimes AUDIT_PATH,
	 * and so on.
	 */

	if (category == CAT_EXECVE) {
#ifdef IGNORE_EMPTY_EXECVE_COMMAND
		/* Didn't get a type=EXECVE message? Then fullcmd will be empty.
		 * This happens when executing scripts for example:
		 * /usr/local/bin/test.sh => exec
		 * => exec /bin/bash
		 * => kernel sends execve syscall for the bash exec without an EXECVE message but a path set to:
		 * dirname(script_path)/exec_name (e.g.: /usr/local/bin/bash in example above).
		 * then fork again for the "real" command (e.g.: /bin/bash /local/bin/test.sh).
		 * While it's correct we only really care for that last command (which has an EXECVE type)
		 * Thus we're skipping the messages without EXECVE altogether, they're mostly noise for our purposes.
		 * It's a little wasteful as we have to free the attributes we've allocated, but as messages can be out of order..
		 * .. we don't really have a choice.
		 */
		if (strlen(fullcmd) == 0) {
			json_del_attrs(json_msg.details);
			return;
		}
#endif
		json_msg.category = "execve";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Execve: %s",
					unescape(fullcmd));
	} else if (category == CAT_WRITE) {
		json_msg.category = "write";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Write: %s",
					unescape(path));
	} else if (category == CAT_ATTR) {
		json_msg.category = "attribute";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Attribute: %s",
					unescape(path));
	} else if (category == CAT_CHMOD) {
		json_msg.category = "chmod";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Chmod: %s",
					unescape(path));
	} else if (category == CAT_CHOWN) {
		json_msg.category = "chown";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Chown: %s",
					unescape(path));
	} else if (category == CAT_PTRACE) {
		json_msg.category = "ptrace";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Ptrace");
	} else if (category == CAT_TIME) {
		json_msg.category = "time";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"time has been modified");
	} else if (category == CAT_PROMISC) {
		json_msg.category = "promiscuous";
		snprintf(json_msg.summary,
					MAX_SUMMARY_LEN,
					"Promisc: Interface %s set promiscous %s",
					unescape(dev), promisc ? "on": "off");
	}

	/* syslog_json_msg() also frees json_msg.details when called. */
	syslog_json_msg(json_msg);
}
