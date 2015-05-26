/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#include "genpasswd.h"

extern struct config conf;

static struct option options[] = {
	{ "help",          no_argument,       0, 0   },
	{ "digit",         required_argument, 0, 'd' },
	{ "alpha",         required_argument, 0, 'a' },
	{ "ALPHA",         required_argument, 0, 'A' },
	{ "special",       required_argument, 0, 's' },
	{ "utf8",          required_argument, 0, 'u' },
	{ "UTF8",          required_argument, 0, 'U' },
	{ "check-entropy", no_argument,       0, 'C' },
	{ "count",         required_argument, 0, 'c' },
	{ "entropy",       required_argument, 0, 'e' },
	{ "length",        required_argument, 0, 'l' },
	{ "no-policy",     no_argument,       0, 'n' },
	{ "show-stats",    no_argument,       0, 'S' },
	{ "table",         no_argument,       0, 't' },
	{ "verbose",       no_argument,       0, 'v' },
	{ 0, 0, 0, 0 },
};

static void usage (struct config *conf, char *name)
{
	char *_name = PROG_NAME;

	if (name && *name)
		_name = name;

	fprintf(stderr, "Usage:\n\t%s [options]\n\n"
			"Where options might be a combination of:\n"
			"\t-h, --help                  Show this help and exit.\n"
			"\t-d, --digit <min>[:<max>]   Include at least <min> digits.\n"
			"\t-a, --alpha <min>[:<max>]   Include at least <min> lower-case letters.\n"
			"\t-A, --ALPHA <min>[:<max>]   Include at least <min> upper-case letters.\n"
			"\t-s, --special <min>[:<max>] Include at least <min> special characters.\n"
			"\t-u, --utf8 <min>[:<max>]    Include at least <min> lower-case UTF-8\n"
			"\t                            characters.\n"
			"\t-U, --UTF8 <min>[:<max>]    Include at least <min> upper-case UTF-8\n"
			"\t                            characters.\n"
			"\t-C, --check-entropy         Don't generate, instead check entropy of\n"
			"\t                            passwords supplied through stdin.\n"
			"\t-c, --count <num>           Number of passwords to generate.\n"
			"\t-e, --entropy <min>[:<max>] Select passwords with entropy inside given\n"
			"\t                            range.\n"
			"\t-l, --length <num>          Password length.\n"
			"\t-n, --no-policy             Don't check password policy.\n"
			"\t-S, --show-stats            Show entropy and statistics for generated\n"
			"\t                            passwords.\n"
			"\t-t, --table                 Print passwords in a table with entropy and\n"
			"\t                            statitistics (implies -S).\n"
			"\t-v, --verbose               Verbose mode.\n"
			"\n",
			_name);

	close(conf->urandom_fd);
	exit(EXIT_SUCCESS);
}

#define PARSE_INTEGER 1
#define PARSE_ENTROPY 2

static int parse_range (struct config *conf, char *optarg, struct range *range, int type)
{
        char *ptr;

	memset(range, 0, sizeof(*range));

        ptr = strchr(optarg, ':');
	if (type == PARSE_INTEGER) {

		if (ptr) {
			range->min = strtoul(optarg, NULL, 10);
			range->max = strtoul(ptr + 1, NULL, 10);
		}
		else {
			range->min = strtoul(optarg, NULL, 10);
			range->max = conf->policy.pwdlen;
		}
	}
	else if (type == PARSE_ENTROPY) {

		if (ptr) {
			range->dmin = strtod(optarg, NULL);
			range->dmax = strtod(ptr + 1, NULL);
		}
		else {
			range->dmin = strtod(optarg, NULL);
			range->dmax = -1.0;
		}
	}
	else {
		return -1;
	}

        if (range->min > range->max)
                return -1;

        return 0;
}

struct config *parse_opts (int argc, char **argv, struct config *conf)
{
	int c, err = 0, policy_set = 0;

	conf->policy.pwdlen = DEFAULT_PASSWD_LEN;
	conf->opt_passwd_count = DEFAULT_PASSWD_COUNT;
	conf->opt_check_policy = 1;

	while (1) {

		c = getopt_long(argc, argv, "hd:a:A:s:u:U:Cc:e:l:nStv", options, NULL);
		if (c == -1)
			break;

		switch (c) {

			case 'h':
				usage(conf, argv[0]);
				break;

			case 'd':
				err = parse_range(conf, optarg, &conf->policy.d, PARSE_INTEGER);
				policy_set = 1;
				break;

			case 'a':
				err = parse_range(conf, optarg, &conf->policy.a, PARSE_INTEGER);
				policy_set = 1;
				break;

			case 'A':
				err = parse_range(conf, optarg, &conf->policy.A, PARSE_INTEGER);
				policy_set = 1;
				break;

			case 's':
				err = parse_range(conf, optarg, &conf->policy.s, PARSE_INTEGER);
				policy_set = 1;
				break;

			case 'u':
				err = parse_range(conf, optarg, &conf->policy.u, PARSE_INTEGER);
				break;

			case 'U':
				err = parse_range(conf, optarg, &conf->policy.U, PARSE_INTEGER);
				break;

			case 'C':
				conf->opt_check_entropy = 1;
				break;

			case 'c':
				conf->opt_passwd_count = strtoul(optarg, NULL, 10);
				break;

			case 'e':
				conf->opt_entropy = 1;
				if (!strcasecmp(optarg, "max")) {
					conf->policy.entropy.min = (size_t)-1.0;
					conf->policy.entropy.max = (size_t)-1.0;
				}
				else {
					err = parse_range(conf, optarg, &conf->policy.entropy, PARSE_ENTROPY);
				}
				break;

			case 'l':
				conf->policy.pwdlen = strtoul(optarg, NULL, 10);
				break;

			case 'n':
				conf->opt_check_policy = 0;
				break;

			case 'S':
				conf->opt_show_stats = 1;
				break;

			case 't':
				conf->opt_show_stats = 1;
				conf->opt_table = 1;
				break;

			case 'v':
				conf->opt_verbose = 1;
				break;

			case '?':
				break;

			default:
				abort();
		}

		if (err)
			usage(conf, argv[0]);
	}

	if (!policy_set) {
		conf->policy.d.max = conf->policy.a.max = conf->policy.A.max = conf->policy.s.max = conf->policy.pwdlen;
		switch (conf->policy.pwdlen) {
			default: conf->policy.d.min = 1;
			case 3:  conf->policy.s.min = 1;
			case 2:  conf->policy.A.min = 1;
			case 1:  conf->policy.a.min = 1;
		}
	}

	return conf;
}

