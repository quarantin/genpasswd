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
#include <limits.h>

#include "genpasswd.h"

extern struct config conf;

typedef enum {
	OPT_END = -1,
	OPT_UNDEFINED = 0,
	OPT_INCOMPLETE,
	OPT_HELP,
	OPT_VERBOSE,
	OPT_TABLE,
	OPT_COUNT,
	OPT_ENTROPY,
	OPT_LENGTH,
	OPT_SHOW_STATS,
	OPT_CHECK_ENTROPY,
	OPT_NO_POLICY,
	OPT_ASCII_DIGIT,
	OPT_ASCII_ALPHA_LOWER,
	OPT_ASCII_ALPHA_UPPER,
	OPT_ASCII_SPECIAL,
	OPT_UTF8_DIGIT,
	OPT_UTF8_ALPHA_LOWER,
	OPT_UTF8_ALPHA_UPPER,
	OPT_UTF8_SPECIAL,
	OPT_SET_ASCII_DIGIT,
	OPT_SET_ASCII_ALPHA_LOWER,
	OPT_SET_ASCII_ALPHA_UPPER,
	OPT_SET_ASCII_SPECIAL,
	OPT_SET_UTF8_DIGIT,
	OPT_SET_UTF8_ALPHA_LOWER,
	OPT_SET_UTF8_ALPHA_UPPER,
	OPT_SET_UTF8_SPECIAL,
} option_id;

typedef enum {
	TYPE_UNDEFINED = -1,
	TYPE_NONE = 0,
	TYPE_REQUIRED,
} argument_type;

struct option {
	option_id id;
	argument_type argtype;
	char *long_name;
	char *short_name;
	char *params;
	char *description;
};

static struct option options[] = {
	{ OPT_HELP,                  TYPE_NONE,     "help",                  "h",   "",              "Show this help and exit." },
	{ OPT_VERBOSE,               TYPE_NONE,     "verbose",               "v",   "",              "Enable verbose mode." },
	{ OPT_TABLE,                 TYPE_NONE,     "table",                 "t",   "",              "Display results in a table with entropy and statistics (implies -s)." },
	{ OPT_COUNT,                 TYPE_REQUIRED, "count",                 "c",   "<count>",       "Number of passwords to generate." },
	{ OPT_ENTROPY,               TYPE_REQUIRED, "entropy",               "e",   "<min>[:<max>]", "Select passwords with entropy in given range." },
	{ OPT_LENGTH,                TYPE_REQUIRED, "length",                "l",   "<lengt>",       "Generate passwords of the given length." },
	{ OPT_SHOW_STATS,            TYPE_NONE,     "show-stats",            "s",   "",              "Show entropy and statistics for generated passwords." },
	{ OPT_CHECK_ENTROPY,         TYPE_NONE,     "check-entropy",         "C",   "",              "Check entropy of passwords supplied through stdin." },
	{ OPT_NO_POLICY,             TYPE_NONE,     "no-policy",             "n",   "",              "Don't check the password policy." },
	{ OPT_ASCII_DIGIT,           TYPE_REQUIRED, "ascii-digit",           "ad",  "<min>[:<max>]", "Include at least <min> ASCII digits in generated passwords but not more than <max>." },
	{ OPT_ASCII_ALPHA_LOWER,     TYPE_REQUIRED, "ascii-alpha-lower",     "al",  "<min>[:<max>]", "Include at least <min> lower-case ASCII characters in generated passwords but not more than <max>." },
	{ OPT_ASCII_ALPHA_UPPER,     TYPE_REQUIRED, "ascii-alpha-upper",     "au",  "<min>[:<max>]", "Include at least <min> lower-case ASCII characters in generated passwords but not more than <max>." },
	{ OPT_ASCII_SPECIAL,         TYPE_REQUIRED, "ascii-special",         "as",  "<min>[:<max>]", "Include at least <min> special ASCII characters in generated passwords but not more than <max>." },
	{ OPT_UTF8_DIGIT,            TYPE_REQUIRED, "utf8-digit",            "ud",  "<min>[:<max>]", "Include at least <min> UTF-8 digits in genrated passwords but not more than <max>." },
	{ OPT_UTF8_ALPHA_LOWER,      TYPE_REQUIRED, "utf8-alpha-lower",      "ul",  "<min>[:<max>]", "Include at least <min> upper-case UTF-8 characters in generated passwords but not more than <max>." },
	{ OPT_UTF8_ALPHA_UPPER,      TYPE_REQUIRED, "utf8-alpha-upper",      "uu",  "<min>[:<max>]", "Include at least <min> in generated passwords but not more than <max>." },
	{ OPT_UTF8_SPECIAL,          TYPE_REQUIRED, "utf8-special",          "us",  "<min>[:<max>]", "Include at least <min> in generated passwords but not more than <max>." },
	{ OPT_SET_ASCII_DIGIT,       TYPE_REQUIRED, "set-ascii-digit",       "sad", "<alphabet>",    "Set a custom alphabet for ASCII digits." },
	{ OPT_SET_ASCII_ALPHA_LOWER, TYPE_REQUIRED, "set-ascii-alpha-lower", "sal", "<alphabet>",    "Set a custom alphabet for lower-case ASCII characters." },
	{ OPT_SET_ASCII_ALPHA_UPPER, TYPE_REQUIRED, "set-ascii-alpha-upper", "sau", "<alphabet>",    "Set a custom alphabet for upper-case ASCII characters." },
	{ OPT_SET_ASCII_SPECIAL,     TYPE_REQUIRED, "set-ascii-special",     "sas", "<alphabet>",    "Set a custom alphabet for special ASCII characters." },
	{ OPT_SET_UTF8_DIGIT,        TYPE_REQUIRED, "set-utf8-digit",        "sud", "<alphabet>",    "Set a custom alphabet for UTF-8 digits." },
	{ OPT_SET_UTF8_ALPHA_LOWER,  TYPE_REQUIRED, "set-utf8-alpha-lower",  "sul", "<alphabet>",    "Set a custom alphabet for lower-case UTF-8 characters." },
	{ OPT_SET_UTF8_ALPHA_UPPER,  TYPE_REQUIRED, "set-utf8-alpha-upper",  "suu", "<alphabet>",    "Set a custom alphabet for upper-case UTF-8 characters." },
	{ OPT_SET_UTF8_SPECIAL,      TYPE_REQUIRED, "set-utf8-special",      "sus", "<alphabet>",    "Set a custom alphabet for special UTF-8 characters." },
};

static size_t options_length = sizeof(options) / sizeof(*options);

static void usage (struct config *conf, char *name)
{
	char *_name = PROG_NAME;
	size_t i, options_length = sizeof(options) / sizeof(*options);

	if (name && *name)
		_name = name;

	fprintf(stderr, "Usage:\n\t%s [options]\n\nWhere options might be a combination of:\n", _name);
	for (i = 0; i < options_length; i++)
		fprintf(stderr, "\t--%s, -%s\t%s\t%s\n",
			options[i].long_name,
			options[i].short_name,
			options[i].params,
			options[i].description);

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

string_t *parse_alphabet (char *alphabet, string_t *string)
{
	int ret;

	if (!alphabet || !*alphabet || !string) {
		fprintf(stderr, "FATAL: Missing argument.\n");
		exit(EXIT_FAILURE);
		return NULL;
	}

	string->len = mbstowcs(NULL, alphabet, 0);
	if (string->len == (size_t)-1) {
		fprintf(stderr, "FATAL: Invalid multibyte sequence encountered, quitting.\n");
		exit(EXIT_FAILURE);
		return NULL;
	}

	string->val = calloc(string->len + 1, sizeof(wchar_t));
	if (!string->val) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
		return NULL;
	}

	ret = swprintf(string->val, string->len + 1, L"%hs", alphabet);
	if (ret < 0 || (unsigned)ret != string->len) {
		perror("swprintf failed");
		free(string->val);
		exit(EXIT_FAILURE);
		return NULL;
	}

	return string;
}

int get_opts (int argc, char **argv, struct option options[], size_t options_length, int *index, char **optarg)
{
	size_t i;
	char *optstr;
	*optarg = NULL;

	if (!index)
		return OPT_UNDEFINED;

	if (*index >= argc)
		return OPT_END;

	if (!argc || !argv || !argv[*index] || argv[*index][0] != '-')
		return OPT_UNDEFINED;

	optstr = argv[*index];
	while (*optstr && *optstr == '-')
		optstr++;

	for (i = 0; i < options_length; i++) {

		if (strcmp(optstr, options[i].long_name) &&
		    strcmp(optstr, options[i].short_name))
			continue;

		(*index)++;
		if (options[i].argtype == TYPE_REQUIRED) {
			//if (*index >= argc)
			//	return OPT_INCOMPLETE;
			//if (!argv[*index])
			//	return OPT_INCOMPLETE;
			*optarg = argv[*index];
			(*index)++;
		}

		return options[i].id;
	}

	return OPT_UNDEFINED;
}

struct config *parse_opts (int argc, char **argv, struct config *conf)
{
	int optval, index = 1;
	//char *optstr;
	char *optarg = NULL;
	int err = 0, policy_set = 0;

	conf->opt_check_policy          = 1;
	conf->shuffle_passes            = 1;
	conf->policy.pwdlen             = DEFAULT_PASSWD_LEN;
	conf->opt_passwd_count          = DEFAULT_PASSWD_COUNT;
	conf->opt_ascii_digit.val       = ASCII_DIGIT_CHARS;
	conf->opt_ascii_digit.len       = ASCII_DIGIT_CHARS_LEN;
	conf->opt_ascii_alpha_lower.val = ASCII_ALPHA_LOWER_CHARS;
	conf->opt_ascii_alpha_lower.len = ASCII_ALPHA_LOWER_CHARS_LEN;
	conf->opt_ascii_alpha_upper.val = ASCII_ALPHA_UPPER_CHARS;
	conf->opt_ascii_alpha_upper.len = ASCII_ALPHA_UPPER_CHARS_LEN;
	conf->opt_ascii_special.val     = ASCII_SPECIAL_CHARS;
	conf->opt_ascii_special.len     = ASCII_SPECIAL_CHARS_LEN;
	conf->opt_utf8_alpha_lower.val  = UTF8_ALPHA_LOWER_CHARS;
	conf->opt_utf8_alpha_lower.len  = UTF8_ALPHA_LOWER_CHARS_LEN;
	conf->opt_utf8_alpha_upper.val  = UTF8_ALPHA_UPPER_CHARS;
	conf->opt_utf8_alpha_upper.len  = UTF8_ALPHA_UPPER_CHARS_LEN;

	while (1) {

		//optstr = argv[index];
		optval = get_opts(argc, argv, options, options_length, &index, &optarg);
		//printf("DEBUG:  ARGC=%02d INDEX=%d ARGV[%d] = '%s' OPTARG = '%s'\n", argc, index, index, optstr, optarg);
		if (optval == OPT_END)
			break;

		switch (optval) {

			case OPT_HELP:
				usage(conf, argv[0]);
				break;

			case OPT_ASCII_DIGIT:
				err = parse_range(conf, optarg, &conf->policy.ascii_digit, PARSE_INTEGER);
				policy_set = 1;
				break;

			case OPT_ASCII_ALPHA_LOWER:
				err = parse_range(conf, optarg, &conf->policy.ascii_alpha_lower, PARSE_INTEGER);
				policy_set = 1;
				break;

			case OPT_ASCII_ALPHA_UPPER:
				err = parse_range(conf, optarg, &conf->policy.ascii_alpha_upper, PARSE_INTEGER);
				policy_set = 1;
				break;

			case OPT_ASCII_SPECIAL:
				err = parse_range(conf, optarg, &conf->policy.ascii_special, PARSE_INTEGER);
				policy_set = 1;
				break;

			case OPT_UTF8_ALPHA_LOWER:
				err = parse_range(conf, optarg, &conf->policy.utf8_alpha_lower, PARSE_INTEGER);
				policy_set = 1;
				break;

			case OPT_UTF8_ALPHA_UPPER:
				err = parse_range(conf, optarg, &conf->policy.utf8_alpha_upper, PARSE_INTEGER);
				policy_set = 1;
				break;

			case OPT_SET_ASCII_DIGIT:
				parse_alphabet(optarg, &conf->opt_ascii_digit);
				break;

			case OPT_SET_ASCII_ALPHA_LOWER:
				parse_alphabet(optarg, &conf->opt_ascii_alpha_lower);
				break;

			case OPT_SET_ASCII_ALPHA_UPPER:
				parse_alphabet(optarg, &conf->opt_ascii_alpha_upper);
				break;

			case OPT_SET_ASCII_SPECIAL:
				parse_alphabet(optarg, &conf->opt_ascii_special);
				break;

			case OPT_SET_UTF8_ALPHA_LOWER:
				parse_alphabet(optarg, &conf->opt_utf8_alpha_lower);
				break;

			case OPT_SET_UTF8_ALPHA_UPPER:
				parse_alphabet(optarg, &conf->opt_utf8_alpha_lower);
				break;

			case OPT_CHECK_ENTROPY:
				conf->opt_check_entropy = 1;
				break;

			case OPT_COUNT:
				conf->opt_passwd_count = strtoul(optarg, NULL, 10);
				break;

			case OPT_ENTROPY:
				conf->opt_entropy = 1;
				if (!strcasecmp(optarg, "max")) {
					conf->policy.entropy.min = (size_t)-1.0;
					conf->policy.entropy.max = (size_t)-1.0;
				}
				else {
					err = parse_range(conf, optarg, &conf->policy.entropy, PARSE_ENTROPY);
				}
				break;

			case OPT_LENGTH:
				conf->policy.pwdlen = strtoul(optarg, NULL, 10);
				break;

			case OPT_NO_POLICY:
				conf->opt_check_policy = 0;
				break;

			case OPT_SHOW_STATS:
				conf->opt_show_stats = 1;
				break;

			case OPT_TABLE:
				conf->opt_show_stats = 1;
				conf->opt_table = 1;
				break;

			case OPT_VERBOSE:
				conf->opt_verbose = 1;
				break;

			case OPT_INCOMPLETE:
				fprintf(stderr, "FATAL: Missing parameter for option: `%s'", argv[index]);
				exit(EXIT_FAILURE);
				break;

			case OPT_UNDEFINED:
				fprintf(stderr, "FATAL: Invalid parameter: `%s'", argv[index]);
				exit(EXIT_FAILURE);
				break;

			default:
				exit(EXIT_FAILURE);
				break;
		}

		if (err)
			usage(conf, argv[0]);
	}

	if (!policy_set) {
		conf->policy.ascii_digit.max = conf->policy.ascii_alpha_lower.max = conf->policy.ascii_alpha_upper.max = conf->policy.ascii_special.max = conf->policy.pwdlen;
		switch (conf->policy.pwdlen) {
			default: conf->policy.ascii_digit.min = 1;
			case 3:  conf->policy.ascii_special.min = 1;
			case 2:  conf->policy.ascii_alpha_upper.min = 1;
			case 1:  conf->policy.ascii_alpha_lower.min = 1;
		}
	}

	return conf;
}

