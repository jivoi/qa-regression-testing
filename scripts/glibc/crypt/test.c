/* Copyright 2011 Canonical, Ltd
   License: GPLv3
   Authors:
	Steve Beattie <steve.beattie@canonical.com>
*/
#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct algs {
	char *name;
	char *salt;
	char *expected_result;
};

struct algs algs[] = {
	{
		.name = "des",
		.salt = "rl",
		.expected_result = "rl0uE0e2WKB0.",
	},
	{
		.name = "md5",
		.salt = "$1$salt$",
		.expected_result = "$1$salt$qJH7.N4xYta3aEG/dfqo/0",
	},
	{
		.name = "sha256",
		.salt = "$5$salt$",
		.expected_result =
			"$5$salt$Gcm6FsVtF/Qa77ZKD.iwsJlCVPY0XSMgLJL0Hnww/c1",
	},
	{
		.name = "sha256-10000",
		.salt = "$5$rounds=10000$salt$",
		.expected_result =
			"$5$rounds=10000$salt$z7k5MrpzwRqIAw4S2Qj6c3ryVeZEqq2vxVSIJyS7UuD",
	},
	{
		.name = "sha512",
		.salt = "$6$salt$",
		.expected_result =
			"$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.",
	},
	{
		.name = "sha512-10000",
		.salt = "$6$rounds=10000$salt$",
		.expected_result =
			"$6$rounds=10000$salt$dE5fLfpn2uXfkz.eouwYK/BjrHRu.piovQPjwlE06fDJHwMlg2l.IqEBUIfWBzf7YPXOAddB3FM7rnXHHKVNt.",
	},
	{
		.name = "blowfish",
		.salt = "$2a$salt$",
		.expected_result =
			"$2a$salt$",
	},
	{  	.name = NULL, }
};

int main(int argc, const char** argv)
{
	struct algs *alg;

	if (argc != 2) {
		printf("Must pass crypt algorithm: md5, blowfish, sha256, sha512\n");
		abort();
	}

	for (alg = algs; alg->name; alg++) {
		if (strcmp(alg->name, argv[1]) == 0) {
			//printf("Found algorithm %s\n", argv[1]);
			break;
		}
	}

	if (alg->name) {
		char *result = crypt("password", alg->salt);
		//printf("%s\n", result);
		if (strcmp(result, alg->expected_result) != 0) {
			printf("Algorithm test for %s FAILED!\n", alg->name);
			printf("Expected: %s\n", alg->expected_result);
			printf("Actual  : %s\n", result);
			abort();
		} else {
			printf("OK\n");
		}
	} else {
		printf("Unable to find algorithm %s in table\n", argv[1]);
		abort();
	}

    	return 0;
}
