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
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "genpasswd.h"

static int urandom_fd;

static int opt_check_policy = 1;
static int opt_check_entropy = 0;
static int opt_min_entropy = 0;
static int opt_table = 0;
static int opt_verbose = 0;
static int opt_passwd_count = DEFAULT_PASSWD_COUNT;

static void usage (char *name)
{
	char *_name = PROG_NAME;

	if (name && *name)
		_name = name;

	fprintf(stderr, "Usage:\n\t%s [options]\n\n"
			"Where options might be a combination of:\n"
			"\t-h, --help                  Show this help and exit.\n"
			"\t-d, --digit <num>           Include at least <num> digits.\n"
			"\t-a, --alpha <num>           Include at least <num> lower case letters.\n"
			"\t-A, --ALPHA <num>           Include at least <num> upper case letters.\n"
			"\t-s, --special <num>         Include at least <num> special characters.\n"
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

	close(urandom_fd);
	exit(EXIT_SUCCESS);
}

static int isspecial (int c)
{
	return c && strchr(SPECIAL_CHARS, c);
}

static void print_char (char c, size_t count, char *eol)
{
	size_t i;

	for (i = 0; i < count; i++)
		putchar(c);

	puts(eol);
}

static int random_num (unsigned char rand_max)
{
	ssize_t ret;
	size_t limit;
	unsigned char rand;

	limit = UCHAR_MAX - ((UCHAR_MAX + 1) % rand_max);

	do {
		ret = read(urandom_fd, &rand, sizeof(rand));
		if (ret != sizeof(rand)) {
			perror("read failed");
			close(urandom_fd);
			exit(EXIT_FAILURE);
		}
	}
	while (rand > limit);

	return (rand % rand_max);
}

static double compute_entropy (const unsigned char *data, size_t datasz)
{
	size_t i;
	double proba, entropy = 0.0;
	unsigned char freqs[UCHAR_MAX + 1];

	memset(freqs, 0, sizeof(freqs));

	for (i = 0; i < datasz; i++)
		freqs[data[i]]++;

	for (i = 0; i < sizeof(freqs); i++) {
		if (freqs[i]) {
			proba = (double)freqs[i] / sizeof(freqs);
			entropy -= proba * log2(proba);
		}
	}

	return entropy * 100;
}

static double compute_best_entropy (struct config *conf, size_t pwdlen)
{
	size_t i;
	double entropy;
	unsigned char *pwd;

	pwd = malloc(pwdlen + 1);
	if (!pwd) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < pwdlen; i++)
		pwd[i] = conf->alphabet[i % conf->alphabet_size];

	pwd[pwdlen] = 0;
	entropy = compute_entropy(pwd, pwdlen);
	free(pwd);
	return entropy;
}

static int policy_ok (struct pwd_policy *policy, unsigned char *pwd, size_t pwdlen)
{
	size_t i;
	int digit = 0, alpha = 0, ALPHA = 0, special = 0;

	for (i = 0; i < pwdlen; i++) {

		if (isdigit(pwd[i]))
			digit++;
		else if (islower(pwd[i]))
			alpha++;
		else if (isupper(pwd[i]))
			ALPHA++;
		else if (isspecial(pwd[i]))
			special++;
		else {
			fprintf(stderr, "Should never happen!\n");
			exit(EXIT_FAILURE);
		}
	}

	return (digit >= policy->min_digit
			&& alpha   >= policy->min_alpha
			&& ALPHA   >= policy->min_ALPHA
			&& special >= policy->min_special);
}

static int find_repetition (struct config *conf, unsigned char *pwd, size_t pwdlen)
{
	int found = 0;
	size_t i, j, size, limit;

	for (size = 0; size < pwdlen; size += conf->alphabet_size) {

		limit = MIN(pwdlen - size, conf->alphabet_size, unsigned int);
		for (i = size; i < size + limit; i++) {
			for (j = i + 1; j < size + limit; j++) {
				if (pwd[i] == pwd[j]) {
					pwd[j] = conf->alphabet[random_num(conf->alphabet_size)];
					found = 1;
				}
			}
		}
	}

	return found;
}

static unsigned char *gen_passwd (struct config *conf, unsigned char *pwd, size_t pwdsz)
{
	int found;
	size_t i;
	size_t pwdlen = conf->policy.pwdlen;

	if (!pwd || !pwdsz)
		return NULL;

	for (i = 0; i < pwdsz; i++)
		pwd[i] = conf->alphabet[random_num(conf->alphabet_size)];

	pwd[pwdsz - 1] = 0;

	while ((found = find_repetition(conf, pwd, pwdlen)))
		;

	if (opt_check_policy && !policy_ok(&conf->policy, pwd, pwdlen))
		return NULL;

	return pwd;
}

static int build_alphabet (struct config *conf)
{
	unsigned char *ptr;

	conf->alphabet = ptr = malloc(512);
	if (!conf->alphabet) {
		perror("malloc failed");
		return -1;
	}

	if (conf->policy.min_digit) {
		conf->alphabet_size += DIGIT_CHARS_LEN;
		memcpy(ptr, DIGIT_CHARS, DIGIT_CHARS_LEN);
		ptr += DIGIT_CHARS_LEN;
	}

	if (conf->policy.min_alpha) {
		conf->alphabet_size += LOWER_CHARS_LEN;
		memcpy(ptr, LOWER_CHARS, LOWER_CHARS_LEN);
		ptr += LOWER_CHARS_LEN;
	}

	if (conf->policy.min_ALPHA) {
		conf->alphabet_size += UPPER_CHARS_LEN;
		memcpy(ptr, UPPER_CHARS, UPPER_CHARS_LEN);
		ptr += UPPER_CHARS_LEN;
	}

	if (conf->policy.min_special) {
		conf->alphabet_size += SPECIAL_CHARS_LEN;
		memcpy(ptr, SPECIAL_CHARS, SPECIAL_CHARS_LEN);
		ptr += SPECIAL_CHARS_LEN;
	}

	*ptr = 0;
	conf->policy.best_entropy = compute_best_entropy(conf, conf->policy.pwdlen);
	return 0;
}

static int count_chars (unsigned char *pwd, size_t pwdlen, int (*ischar) (int c))
{
	size_t i = 0;
	int count = 0;

	for (i = 0; i < pwdlen; i++) {
		if (ischar(pwd[i]))
			count++;
	}

	return count;
}

static struct config *parse_opts (int argc, char **argv, struct config *conf)
{
	int i;

	for (i = 1; i < argc; i++) {

		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
		}
		else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--digit")) {
			conf->policy.min_digit = strtoul(argv[i + 1], NULL, 10);
			i++;
		}
		else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--alpha")) {
			conf->policy.min_alpha = strtoul(argv[i + 1], NULL, 10);
			i++;
		}
		else if (!strcmp(argv[i], "-A") || !strcmp(argv[i], "--ALPHA")) {
			conf->policy.min_ALPHA = strtoul(argv[i + 1], NULL, 10);
			i++;
		}
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--special")) {
			conf->policy.min_special = strtoul(argv[i + 1], NULL, 10);
			i++;
		}
		else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--length")) {
			conf->policy.pwdlen = strtoul(argv[i + 1], NULL, 10);
			i++;
		}
		else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--min-entropy")) {
			opt_min_entropy = 1;
			conf->policy.min_entropy = strtod(argv[i + 1], NULL);
			i++;
		}
		else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--no-policy")) {
			opt_check_policy = 0;
		}
		else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--count")) {
			opt_passwd_count = strtoul(argv[i + 1], NULL, 10);
			i++;
		}
		else if (!strcmp(argv[i], "-e") || !strcmp(argv[i], "--check-entropy")) {
			opt_check_entropy = 1;
		}
		else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--table")) {
			opt_table = 1;
		}
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
			opt_verbose = 1;
		}
		else {
			fprintf(stderr, "FATAL: Invalid option: `%s'\n", argv[i]);
			usage(argv[0]);
		}
	}

	if (!conf->policy.pwdlen)
		conf->policy.pwdlen = DEFAULT_PASSWD_LEN;

	if (!conf->policy.min_digit
			&& !conf->policy.min_alpha
			&& !conf->policy.min_ALPHA
			&& !conf->policy.min_special)
	{
		switch (conf->policy.pwdlen) {
			default: conf->policy.min_digit   = 1;
			case 3:  conf->policy.min_special = 1;
			case 2:  conf->policy.min_ALPHA   = 1;
			case 1:  conf->policy.min_alpha   = 1;
		}
	}

	build_alphabet(conf);
	return conf;
}

static void get_pwd_stats (unsigned char *pwd, size_t pwdlen, struct pwd_policy *policy)
{
	policy->entropy     = compute_entropy(pwd, pwdlen);
	policy->min_digit   = count_chars(pwd, pwdlen, isdigit);
	policy->min_alpha   = count_chars(pwd, pwdlen, islower);
	policy->min_ALPHA   = count_chars(pwd, pwdlen, isupper);
	policy->min_special = count_chars(pwd, pwdlen, isspecial);
}

static void print_passwd (unsigned char *pwd, size_t pwdlen, struct pwd_policy *stat)
{
	int padding;

	if (!opt_table) {
		printf("%s\n", pwd);
	}
	else {
		printf("| %lf | d:%02d a:%02d A:%02d s:%02d | %s",
				stat->entropy,
				stat->min_digit,
				stat->min_alpha,
				stat->min_ALPHA,
				stat->min_special,
				pwd);

		padding = (pwdlen > 7) ? 1 : 9 - pwdlen;
		print_char(' ', padding, "|");
	}
}

static void check_entropy (void)
{
	size_t pwdlen;
	char *ptr, pwd[BUFSIZ];
	struct pwd_policy stat;

	while (fgets(pwd, sizeof(pwd), stdin)) {

		ptr = strchr(pwd, '\n');
		if (ptr)
			*ptr = 0;

		pwdlen = strlen(pwd);

		memset(&stat, 0, sizeof(stat));
		get_pwd_stats((unsigned char *)pwd, pwdlen, &stat);
		print_passwd((unsigned char *)pwd, pwdlen, &stat);
		memset(pwd, 0, pwdlen);
	}
}

static void generate_passwords (struct config *conf)
{
	int i;
	size_t pwdlen;
	unsigned char *pwd;
	struct pwd_policy stat;

	pwdlen = conf->policy.pwdlen;
	pwd = malloc(pwdlen + 1);
	if (!pwd) {
		perror("malloc failed");
		return;
	}

	for (i = 0; i < opt_passwd_count;) {

		if (gen_passwd(conf, pwd, pwdlen + 1)) {

			memset(&stat, 0, sizeof(stat));
			get_pwd_stats(pwd, pwdlen, &stat);
			if (opt_min_entropy && stat.entropy < conf->policy.min_entropy)
				continue;

			print_passwd(pwd, pwdlen, &stat);
			memset(pwd, 0, pwdlen);
			i++;
		}
	}

	free(pwd);
}

int main (int argc, char **argv)
{
	int pad;
	size_t pwdlen;
	struct config conf;
	double best_entropy;
	char padspacer[32];
	char padborder[32];

	if (!argc || !argv || !*argv) {
		fprintf(stderr, "FATAL: Invalid arguments.\n");
		exit(EXIT_FAILURE);
	}

	memset(&conf, 0, sizeof(conf));
	if (!parse_opts(argc, argv, &conf)) {
		fprintf(stderr, "FATAL: Failed parsing options.\n");
		exit(EXIT_FAILURE);
	}

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		perror("open failed");
		exit(EXIT_FAILURE);
	}

	pwdlen = conf.policy.pwdlen;

	best_entropy = conf.policy.best_entropy;
	if (conf.policy.min_entropy == 0.0)
		conf.policy.min_entropy = best_entropy;

	if (opt_table && opt_verbose) {
		printf("Symbols: %lu\n", conf.alphabet_size);
		printf("Alphabet: %s\n", conf.alphabet);
		printf("Password length: %lu\n", pwdlen);
		printf("Best entropy for length: %lf\n", best_entropy);
	}

	pad = (int)log10(best_entropy);
	memset(padspacer, ' ', pad);
	memset(padborder, '_', pad);
	padspacer[pad] = 0;
	padborder[pad] = 0;

	pad = (pwdlen > 7) ? pwdlen : 8;
	if (opt_table) {
		printf(" _________%s__________________________",         padborder); print_char('_', pad, "");
		printf("|         %s |                     |  ",         padspacer); print_char(' ', pad, "|");
		printf("|  Entropy%s |       Stats         | Password ", padspacer); print_char(' ', MAX(0, pwdlen - 8, int), "|");
		printf("|_________%s_|_____________________|__",         padborder); print_char('_', pad, "|");
	}

	opt_check_entropy ? check_entropy() : generate_passwords(&conf);

	if (opt_table) {
		printf("|_________%s_|_____________________|__", padborder); print_char('_', pad, "|");
	}

	free(conf.alphabet);
	close(urandom_fd);
	exit(EXIT_SUCCESS);
	return 0;
}

