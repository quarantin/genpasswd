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

static size_t passwd_count = DEFAULT_PASSWD_COUNT;

static unsigned char alphabet[512];
static size_t alphabet_size;

static int opt_check_policy = 1;
static int opt_check_entropy = 0;
static int opt_table = 0;
static int opt_verbose = 0;

static void usage (char *name)
{
	char *_name = PROG_NAME;

	if (name && *name)
		_name = name;

	fprintf(stderr, "Usage:\n\t%s [options]\n\n"
			"Where options might be a combination of:\n"
			"\t\t-d, --digit <num>           include at least <num> digits.\n"
			"\t\t-a, --alpha <num>           include at least <num> lower case letters.\n"
			"\t\t-A, --ALPHA <num>           include at least <num> upper case letters.\n"
			"\t\t-s, --special <num>         include at least <num> special characters.\n"
			"\t\t-l, --length <num>          password length.\n"
			"\t\t-m, --min-entropy <double>  minimum entropy for passwords.\n"
			"\t\t-c, --check-entropy         don't generate passwords, instead check\n"
			"\t\t                            entropy of passwords supplied through stdin.\n"
			"\t\t-n, --no-policy             don't check password policy.\n"
			"\t\t-t, --table                 print passwords in a table with headers.\n"
			"\t\t-v, --verbose               verbose mode.\n",
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
	unsigned char stats[256];
	double proba, entropy = 0.0;

	memset(stats, 0, sizeof(stats));

	for (i = 0; i < datasz; i++)
		stats[data[i]]++;

	for (i = 0; i < sizeof(stats); i++) {
		if (stats[i]) {
			proba = (double)stats[i] / 256;
			entropy -= proba * log2(proba);
		}
	}

	return entropy * 100;
}

static int policy_ok (unsigned char *pwd, size_t pwdlen, struct pwd_policy *policy)
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

static unsigned char *find_repetition (unsigned char *passwd, size_t passwdsz)
{
	size_t i, j;

	for (i = 0; i < passwdsz; i++) {
		for (j = i + 1; j < passwdsz; j++) {
			if (passwd[i] == passwd[j])
				return &passwd[j];
		}
	}

	return NULL;
}

static unsigned char *gen_passwd (unsigned char *pwd, size_t pwdsz, struct pwd_policy *policy)
{
	size_t i;
	size_t pwdlen = policy->pwdlen;

	unsigned char *ptr;

	if (!pwd || !pwdsz)
		return NULL;

	for (i = 0; i < pwdsz; i++)
		pwd[i] = alphabet[random_num(alphabet_size)];

	pwd[pwdsz - 1] = 0;

	if (policy->pwdlen <= alphabet_size) {

		do {
			ptr = find_repetition(pwd, pwdlen);
			if (ptr)
				*ptr = alphabet[random_num(alphabet_size)];
		} while (ptr);
	}

	if (opt_check_policy && !policy_ok(pwd, pwdlen, policy))
		return NULL;

	return pwd;
}

static void build_alphabet (struct config *conf)
{
	unsigned char *ptr = alphabet;

	if (conf->policy.min_digit) {
		alphabet_size += DIGIT_CHARS_LEN;
		memcpy(ptr, DIGIT_CHARS, DIGIT_CHARS_LEN);
		ptr += DIGIT_CHARS_LEN;
	}

	if (conf->policy.min_alpha) {
		alphabet_size += LOWER_CHARS_LEN;
		memcpy(ptr, LOWER_CHARS, LOWER_CHARS_LEN);
		ptr += LOWER_CHARS_LEN;
	}

	if (conf->policy.min_ALPHA) {
		alphabet_size += UPPER_CHARS_LEN;
		memcpy(ptr, UPPER_CHARS, UPPER_CHARS_LEN);
		ptr += UPPER_CHARS_LEN;
	}

	if (conf->policy.min_special) {
		alphabet_size += SPECIAL_CHARS_LEN;
		memcpy(ptr, SPECIAL_CHARS, SPECIAL_CHARS_LEN);
		ptr += SPECIAL_CHARS_LEN;
	}

	*ptr = 0;
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

		if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--digit")) {
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
			conf->policy.min_entropy = strtod(argv[i + 1], NULL);
			i++;
		}
		else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--no-policy")) {
			opt_check_policy = 0;
		}
		else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--check-entropy")) {
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
			return NULL;
		}
	}

	if (!conf->policy.pwdlen) {
		fprintf(stderr, "FATAL: Invalid password length: Can't be zero.\n");
		return NULL;
	}

	if (!conf->policy.min_digit
			&& !conf->policy.min_alpha
			&& !conf->policy.min_ALPHA
			&& !conf->policy.min_special) {
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

static void print_passwd (unsigned char *pwd, size_t pwdlen)
{
	if (!opt_table) {
		printf("%s\n", pwd);
	}
	else {
		int padding;
		struct pwd_policy stat;
		char *border = (opt_table ? "|" : "");

		memset(&stat, 0, sizeof(stat));
		get_pwd_stats(pwd, pwdlen, &stat);
		printf("%s %lf | d:%02d,a:%02d,A:%02d,s:%02d | %s",
				border,
				stat.entropy,
				stat.min_digit,
				stat.min_alpha,
				stat.min_ALPHA,
				stat.min_special,
				pwd);

		padding = (pwdlen > 7) ? 1 : 9 - pwdlen;
		print_char(' ', padding, border);
	}
}

static void check_entropy (void)
{
	size_t pwdlen;
	char *ptr, pwd[BUFSIZ];

	while (fgets(pwd, sizeof(pwd), stdin)) {

		ptr = strchr(pwd, '\n');
		if (ptr)
			*ptr = 0;

		pwdlen = strlen(pwd);
		print_passwd((unsigned char *)pwd, pwdlen);
		memset(pwd, 0, pwdlen);
	}
}

static void generate_passwords (unsigned char *pwd, size_t pwdlen, struct config *conf)
{
	size_t i;

	for (i = 0; i < passwd_count;) {

		if (gen_passwd(pwd, pwdlen + 1, &conf->policy)) {
			print_passwd(pwd, pwdlen);
			memset(pwd, 0, pwdlen);
			i++;
		}
	}
}

int main (int argc, char **argv)
{
	int pad;
	size_t i, pwdlen;
	unsigned char *pwd;
	struct config conf;
	double best_entropy;
	char padspacer[32];
	char padborder[32];
	unsigned char entropy_buffer[256];

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
	pwd = malloc(pwdlen + 1);
	if (!pwd) {
		perror("malloc failed");
		close(urandom_fd);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < 256; i++)
		entropy_buffer[i] = i;

	best_entropy = compute_entropy(entropy_buffer, pwdlen);
	if (conf.policy.min_entropy == 0.0)
		conf.policy.min_entropy = best_entropy;

	if (opt_table && opt_verbose) {
		printf("Symbols: %lu\n", alphabet_size);
		printf("Alphabet: %s\n", alphabet);
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
		printf("|  Entropy%s |       Stats         | Password ", padspacer); print_char(' ', MAX(0, pwdlen - 8), "|");
		printf("|_________%s_|_____________________|__",         padborder); print_char('_', pad, "|");
	}

	if (opt_check_entropy) {
		check_entropy();
	}
	else {
		generate_passwords(pwd, pwdlen, &conf);
	}

	if (opt_table) {
		printf("|_________%s_|_____________________|__", padborder); print_char('_', pad, "|");
	}

	free(pwd);
	close(urandom_fd);
	exit(EXIT_SUCCESS);
	return 0;
}

