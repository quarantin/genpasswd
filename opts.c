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
	{ "count",         required_argument, 0, 'c' },
	{ "length",        required_argument, 0, 'l' },
	{ "min-entropy",   required_argument, 0, 'm' },
	{ "check-entropy", required_argument, 0, 'e' },
	{ "no-policy",     no_argument,       0, 'n' },
	{ "table",         no_argument,       0, 't' },
	{ "verbose",       no_argument,       0, 'v' },
	{ 0, 0, 0, 0 },
};

static void usage (char *name)
{
	char *_name = PROG_NAME;

	if (name && *name)
		_name = name;

	fprintf(stderr, "Usage:\n\t%s [options]\n\n"
			"Where options might be a combination of:\n"
			"\t-h, --help                  Show this help and exit.\n"
			"\t-d, --digit <min>[:<max>]   Include at least <min> digits.\n"
			"\t-a, --alpha <min>[:<max>]   Include at least <min> lower case letters.\n"
			"\t-A, --ALPHA <min>[:<max>]   Include at least <min> upper case letters.\n"
			"\t-s, --special <min>[:<max>] Include at least <min> special characters.\n"
			"\t-u, --utf8 <min>[:<max>]    Include at least <min> UTF-8 characters.\n"
			"\t-l, --length <num>          Password length.\n"
			"\t-m, --min-entropy <double>  Minimum entropy in bits.\n"
			"\t-c, --count <num>           Number of passwords to generate.\n"
			"\t-e, --check-entropy         Don't generate, instead check entropy of\n"
			"\t                            passwords supplied through stdin.\n"
			"\t-n, --no-policy             Don't check password policy.\n"
			"\t-t, --table                 Print passwords in a table with entropy and\n"
			"\t                            statitistics.\n"
			"\t-v, --verbose               Verbose mode.\n"
			"\n",
			_name);

	close(conf.urandom_fd);
	exit(EXIT_SUCCESS);
}

static int parse_range (char *optarg, struct range *range)
{
        char *ptr;

        ptr = strchr(optarg, ':');
        if (ptr) {
                range->min = strtoul(optarg, NULL, 10);
                range->max = strtoul(ptr + 1,     NULL, 10);
        }
        else {
                range->min = strtoul(optarg, NULL, 10);
                range->max = INT_MAX;
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

		c = getopt_long(argc, argv, "hd:a:A:s:u:c:l:m:netv", options, NULL);
		if (c == -1)
			break;

		switch (c) {

			case 'h':
				usage(argv[0]);
				break;

			case 'd':
				err = parse_range(optarg, &conf->policy.d);
				policy_set = 1;
				break;

			case 'a':
				err = parse_range(optarg, &conf->policy.a);
				policy_set = 1;
				break;

			case 'A':
				err = parse_range(optarg, &conf->policy.A);
				policy_set = 1;
				break;

			case 's':
				err = parse_range(optarg, &conf->policy.s);
				policy_set = 1;
				break;

			case 'u':
				err = parse_range(optarg, &conf->policy.u);
				break;

			case 'c':
				conf->opt_passwd_count = strtoul(optarg, NULL, 10);
				break;

			case 'l':
				conf->policy.pwdlen = strtoul(optarg, NULL, 10);
				break;

			case 'm':
				conf->opt_min_entropy = 1;
				conf->policy.min_entropy = strtod(optarg, NULL);
				break;

			case 'n':
				conf->opt_check_policy = 0;
				break;

			case 'e':
				conf->opt_check_entropy = 1;
				break;

			case 't':
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
			usage(argv[0]);
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
