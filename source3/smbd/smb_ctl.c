#include "includes.h"
#include "system/filesys.h"
#include "lib/util/server_id.h"
#include "popt_common.h"
#include "librpc/gen_ndr/spoolss.h"
#include "nt_printing.h"
#include "printing/notify.h"
#include "libsmb/nmblib.h"
#include "messages.h"
#include "util_tdb.h"
#include "../lib/util/pidfile.h"
#include "serverid.h"
#include "cmdline_contexts.h"
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"

/* Default timeout value when waiting for replies (in seconds) */

#define DEFAULT_TIMEOUT 10

static int timeout = DEFAULT_TIMEOUT;
static int num_replies;		/* Used by message callback fns */

/* Send a message to a destination pid.  Zero means broadcast smbd. */

static bool send_message(struct messaging_context *msg_ctx,
			 struct server_id pid, int msg_type,
			 const void *buf, int len)
{
	if (procid_to_pid(&pid) != 0)
		return NT_STATUS_IS_OK(
			messaging_send_buf(msg_ctx, pid, msg_type,
					   (const uint8_t *)buf, len));

	messaging_send_all(msg_ctx, msg_type, buf, len);

	return true;
}

static void smbcontrol_timeout(struct tevent_context *event_ctx,
			       struct tevent_timer *te,
			       struct timeval now,
			       void *private_data)
{
	bool *timed_out = (bool *)private_data;
	TALLOC_FREE(te);
	*timed_out = True;
}

/* Wait for one or more reply messages */

static void wait_replies(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 bool multiple_replies)
{
	struct tevent_timer *te;
	bool timed_out = False;

	te = tevent_add_timer(ev_ctx, NULL,
			      timeval_current_ofs(timeout, 0),
			      smbcontrol_timeout, (void *)&timed_out);
	if (te == NULL) {
		DEBUG(0, ("tevent_add_timer failed\n"));
		return;
	}

	while (!timed_out) {
		int ret;
		if (num_replies > 0 && !multiple_replies)
			break;
		ret = tevent_loop_once(ev_ctx);
		if (ret != 0) {
			break;
		}
	}
}

/* Ping a samba daemon process */

static void pong_cb(struct messaging_context *msg,
		    void *private_data, 
		    uint32_t msg_type, 
		    struct server_id pid,
		    DATA_BLOB *data)
{
	struct server_id_buf src_string;
	printf("PONG from pid %s\n", server_id_str_buf(pid, &src_string));
	num_replies++;
}

static bool do_ping(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx,
		    const struct server_id pid,
		    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> ping\n");
		return False;
	}

	/* Send a message and register our interest in a reply */

	if (!send_message(msg_ctx, pid, MSG_PING, NULL, 0))
		return False;

	messaging_register(msg_ctx, NULL, MSG_PONG, pong_cb);

	wait_replies(ev_ctx, msg_ctx, procid_to_pid(&pid) == 0);

	/* No replies were received within the timeout period */

	if (num_replies == 0)
		printf("No replies received\n");

	messaging_deregister(msg_ctx, MSG_PONG, NULL);

	return num_replies;
}

/* Shutdown a server process */

static bool do_shutdown(struct tevent_context *ev_ctx,
			struct messaging_context *msg_ctx,
			const struct server_id pid,
			const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> shutdown\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_SHUTDOWN, NULL, 0);
}

static bool do_reload_config(struct tevent_context *ev_ctx,
			     struct messaging_context *msg_ctx,
			     const struct server_id pid,
			     const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> reload-config\n");
		return False;
	}

	return send_message(msg_ctx, pid, MSG_SMB_CONF_UPDATED, NULL, 0);
}

/* Send no message.  Useful for testing. */

static bool do_noop(struct tevent_context *ev_ctx,
		    struct messaging_context *msg_ctx,
		    const struct server_id pid,
		    const int argc, const char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: smbcontrol <dest> noop\n");
		return False;
	}

	/* Move along, nothing to see here */

	return True;
}

/* A list of message type supported */

static const struct {
	const char *name;	/* Option name */
	bool (*fn)(struct tevent_context *ev_ctx,
		   struct messaging_context *msg_ctx,
		   const struct server_id pid,
		   const int argc, const char **argv);
	const char *help;	/* Short help text */
} msg_types[] = {
	{
		.name = "ping",
		.fn   = do_ping,
		.help = "Elicit a response",
	},
	{
		.name = "shutdown",
		.fn   = do_shutdown,
		.help = "Shut down daemon",
	},
	{
		.name = "reload-config",
		.fn   = do_reload_config,
		.help = "Force smbd or winbindd to reload config file",
	},
	{
		.name = "noop",
		.fn   = do_noop,
		.help = "Do nothing",
	},
	{ .name = NULL, },
};

static void usage(poptContext pc)
{
	int i;

	poptPrintHelp(pc, stderr, 0);

	fprintf(stderr, "\n");
	fprintf(stderr, "<destination> is one of \"nmbd\", \"smbd\", \"winbindd\" or a "
		"process ID\n");

	fprintf(stderr, "\n");
	fprintf(stderr, "<message-type> is one of:\n");

	for (i = 0; msg_types[i].name; i++) {
		const char *help = msg_types[i].help;
		if (help == NULL) {
			help = "";
		}
		fprintf(stderr, "\t%-30s%s\n", msg_types[i].name, help);
	}

	fprintf(stderr, "\n");

	exit(1);
}

/* Return the pid number for a string destination */

static struct server_id parse_dest(struct messaging_context *msg,
				   const char *dest)
{
	struct server_id result = {
		.pid = (uint64_t)-1,
	};
	pid_t pid;

	/* Zero is a special return value for broadcast to all processes */

	if (strequal(dest, "all")) {
		return interpret_pid(MSG_BROADCAST_PID_STR);
	}

	/* Try self - useful for testing */

	if (strequal(dest, "self")) {
		return messaging_server_id(msg);
	}

	/* Fix winbind typo. */
	if (strequal(dest, "winbind")) {
		dest = "winbindd";
	}

	/* Check for numeric pid number */
	result = interpret_pid(dest);

	/* Zero isn't valid if not "all". */
	if (result.pid && procid_valid(&result)) {
		return result;
	}

	/* Look up other destinations in pidfile directory */

	if ((pid = pidfile_pid(lp_pid_directory(), dest)) != 0) {
		return pid_to_procid(pid);
	}

	fprintf(stderr,"Can't find pid for destination '%s'\n", dest);

	return result;
}

/* Execute smbcontrol command */

static bool do_command(struct tevent_context *ev_ctx,
		       struct messaging_context *msg_ctx,
		       int argc, const char **argv)
{
	const char *dest = argv[0], *command = argv[1];
	struct server_id pid;
	int i;

	/* Check destination */

	pid = parse_dest(msg_ctx, dest);
	if (!procid_valid(&pid)) {
		return False;
	}

	/* Check command */

	for (i = 0; msg_types[i].name; i++) {
		if (strequal(command, msg_types[i].name))
			return msg_types[i].fn(ev_ctx, msg_ctx, pid,
					       argc - 1, argv + 1);
	}

	fprintf(stderr, "smbcontrol: unknown command '%s'\n", command);

	return False;
}

static void smbcontrol_help(poptContext pc,
		    enum poptCallbackReason preason,
		    struct poptOption * poption,
		    const char * parg,
		    void * pdata)
{
	if (poption->shortName != '?') {
		poptPrintUsage(pc, stdout, 0);
	} else {
		usage(pc);
	}

	exit(0);
}

struct poptOption help_options[] = {
	{ NULL, '\0', POPT_ARG_CALLBACK, (void *)&smbcontrol_help, '\0',
	  NULL, NULL },
	{ "help", '?', 0, NULL, '?', "Show this help message", NULL },
	{ "usage", '\0', 0, NULL, 'u', "Display brief usage message", NULL },
	{0}
} ;


int main_ctl(int argc,const char *argv[]) {
	poptContext pc;
	int opt;
	struct tevent_context *evt_ctx;
	struct messaging_context *msg_ctx;

	static struct poptOption long_options[] = {
		/* POPT_AUTOHELP */
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, help_options,
		                        0, "Help options:", NULL },
		{ "timeout", 't', POPT_ARG_INT, &timeout, 't', 
		  "Set timeout value in seconds", "TIMEOUT" },

		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = 0;

	smb_init_locale();

	setup_logging(argv[0], DEBUG_STDOUT);
	lp_set_cmdline("log level", "0");

	/* Parse command line arguments using popt */

	pc = poptGetContext(
		"smbcontrol", argc, (const char **)argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "[OPTION...] <destination> <message-type> "
			       "<parameters>");

	if (argc == 1)
		usage(pc);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		case 't':	/* --timeout */
			break;
		default:
			fprintf(stderr, "Invalid option\n");
			poptPrintHelp(pc, stderr, 0);
			break;
		}
	}

	/* We should now have the remaining command line arguments in
           argv.  The argc parameter should have been decremented to the
           correct value in the above switch statement. */

	argv = (const char **)poptGetArgs(pc);
	argc = 0;
	if (argv != NULL) {
		while (argv[argc] != NULL) {
			argc++;
		}
	}

	if (argc <= 1)
		usage(pc);

	msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());
	if (msg_ctx == NULL) {
		fprintf(stderr,
			"Could not init messaging context, not root?\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	evt_ctx = global_event_context();

	lp_load_global(get_dyn_CONFIGFILE());

	/* Need to invert sense of return code -- samba
         * routines mostly return True==1 for success, but
         * shell needs 0. */ 

	ret = !do_command(evt_ctx, msg_ctx, argc, argv);

	cmdline_messaging_context_free();
	poptFreeContext(pc);
	TALLOC_FREE(frame);
	return ret;
}

