/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus_message.c  Utility program to send messages from the command line
 *
 * Copyright (C) 2003 Philip Blundell <philb@gnu.org>
 * Copyright (C) 2013 Canonical, Ltd.
 *
 * Originally dbus-send.c from the dbus package. It has been heavily modified
 * to work within the regression test framework.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dbus/dbus.h>

DBusConnection *connection;
DBusError error;
DBusBusType type = DBUS_BUS_SESSION;
const char *type_str = NULL;
const char *name = NULL;
const char *interface = NULL;
const char *member = NULL;
const char *path = NULL;
int message_type = DBUS_MESSAGE_TYPE_SIGNAL;
const char *address = NULL;
int session_or_system = FALSE;
const char *message_contents = "ping";

static void usage(int ecode)
{
	char *prefix = ecode ? "FAIL: " : "";

	fprintf(stderr,
		"%6sUsage: dbus_message [ADDRESS] [--name=NAME] [--type=TYPE] <path> <interface.member> [contents ...]\n"
		"    ADDRESS\t\t--system, --session (default), or --address=ADDR\n"
		"    NAME\t\tthe message destination\n"
		"    TYPE\t\tsignal (default) or method_call\n"
		"    path\t\tpath to object (such as /org/freedesktop/DBus)\n"
		"    interface\t\tinterface to use (such as org.freedesktop.DBus)\n"
		"    member\t\tname of the method or signal (such as ListNames)\n",
		prefix);
	exit(ecode);
}

static int do_message()
{
	DBusMessage *message;
	DBusMessageIter iter;

	if (message_type == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		message = dbus_message_new_method_call(NULL,
						       path, interface, member);
		dbus_message_set_auto_start(message, TRUE);
	} else if (message_type == DBUS_MESSAGE_TYPE_SIGNAL) {
		message = dbus_message_new_signal(path, interface, member);
	} else {
		fprintf(stderr, "FAIL: Internal error, unknown message type\n");
		return 1;
	}

	if (message == NULL) {
		fprintf(stderr, "FAIL: Couldn't allocate D-Bus message\n");
		return 1;
	}

	if (name && !dbus_message_set_destination(message, name)) {
		fprintf(stderr, "FAIL: Not enough memory\n");
		return 1;
	}

	dbus_message_iter_init_append(message, &iter);
	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
					    &message_contents)) {
		fprintf(stderr, "FAIL: Not enough memory\n");
		return 1;
	}

	if (message_type == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		DBusMessage *reply;

		dbus_error_init(&error);
		reply = dbus_connection_send_with_reply_and_block(connection,
								  message, -1,
								  &error);
		if (dbus_error_is_set(&error)) {
			fprintf(stderr, "FAIL: %s: %s\n",
				error.name, error.message);
			return 1;
		}

		if (reply) {
			dbus_message_unref(reply);
		}
	} else {
		dbus_connection_send(connection, message, NULL);
		dbus_connection_flush(connection);
	}

	dbus_message_unref(message);

	return 0;
}

int main(int argc, char *argv[])
{
	int i, rc;

	if (argc < 3)
		usage(1);

	for (i = 1; i < argc && interface == NULL; i++) {
		char *arg = argv[i];

		if (strcmp(arg, "--system") == 0) {
			type = DBUS_BUS_SYSTEM;
			session_or_system = TRUE;
		} else if (strcmp(arg, "--session") == 0) {
			type = DBUS_BUS_SESSION;
			session_or_system = TRUE;
		} else if (strstr(arg, "--address") == arg) {
			address = strchr(arg, '=');

			if (address == NULL) {
				fprintf(stderr,
					"FAIL: \"--address=\" requires an ADDRESS\n");
				usage(1);
			} else {
				address = address + 1;
			}
		} else if (strstr(arg, "--name=") == arg)
			name = strchr(arg, '=') + 1;
		else if (strstr(arg, "--type=") == arg)
			type_str = strchr(arg, '=') + 1;
		else if (!strcmp(arg, "--help"))
			usage(0);
		else if (arg[0] == '-')
			usage(1);
		else if (path == NULL)
			path = arg;
		else	/* interface == NULL guaranteed by the 'while' loop */
			interface = arg;
	}

	if (interface == NULL)
		usage(1);
	else {
		char *last_dot = strrchr(interface, '.');

		if (last_dot == NULL) {
			fprintf(stderr,
				"FAIL: Must use org.mydomain.Interface.Member notation, no dot in \"%s\"\n",
				interface);
			exit(1);
		}
		*last_dot = '\0';
		member = last_dot + 1;
	}

	if (session_or_system && address != NULL) {
		fprintf(stderr,
			"FAIL: \"--address\" may not be used with \"--system\" or \"--session\"\n");
		usage(1);
	}

	if (type_str != NULL) {
		message_type = dbus_message_type_from_string(type_str);
		if (!(message_type == DBUS_MESSAGE_TYPE_METHOD_CALL ||
		      message_type == DBUS_MESSAGE_TYPE_SIGNAL)) {
			fprintf(stderr,
				"FAIL: Message type \"%s\" is not supported\n",
				type_str);
			exit(1);
		}
		if (message_type == DBUS_MESSAGE_TYPE_METHOD_CALL && !name) {
			fprintf(stderr,
				"FAIL: method_call messages must specify a destination name\n");
			exit(1);
		}
	}

	dbus_error_init(&error);

	if (address != NULL)
		connection = dbus_connection_open(address, &error);
	else
		connection = dbus_bus_get(type, &error);

	if (connection == NULL) {
		fprintf(stderr,
			"FAIL: Failed to open connection to \"%s\" message bus: %s\n",
			(address !=
			 NULL) ? address : ((type ==
					     DBUS_BUS_SYSTEM) ? "system" :
					    "session"), error.message);
		dbus_error_free(&error);
		exit(1);
	} else if (address != NULL)
		dbus_bus_register(connection, &error);

	rc = do_message();
	dbus_connection_unref(connection);
	if (rc == 0)
		printf("PASS\n");

	exit(rc);
}
