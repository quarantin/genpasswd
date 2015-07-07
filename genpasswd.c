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
#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <wctype.h>
#include <search.h>

#include "genpasswd.h"
#include "htable.h"
#include "opts.h"

static struct config conf;

static int quit (int status)
{
	close(conf.urandom_fd);
	free(conf.alphabet);
	exit(status);
}

static int iswspecial (wchar_t wc)
{
	return wcschr(conf.opt_ascii_special.val, wc) ? 1 : 0;
}

static int isutf8lower (wchar_t wc)
{
	if (iswlower(wc))
		return wcschr(conf.opt_utf8_alpha_lower.val, wc) ? 1 : 0;

	return 0;
}

static int isutf8upper (wchar_t wc)
{
	if (iswupper(wc))
		return wcschr(conf.opt_utf8_alpha_upper.val, wc) ? 1 : 0;

	return 0;
}

static unsigned int random_num (int urandom_fd, size_t rand_max)
{
	ssize_t ret;
	unsigned int limit, rand;

	limit = UINT_MAX - (UINT_MAX % rand_max);

	do {
		ret = read(urandom_fd, &rand, sizeof(rand));
		if (ret != sizeof(rand)) {
			perror("read failed");
			close(urandom_fd);
			exit(EXIT_FAILURE);
		}
	}
	while (rand > limit);

	//printf("UINT_MAX = %u, limit = %u, rand_max = %lu, RAND = %lu\n", UINT_MAX, limit, rand_max, (rand % rand_max));
	return (rand % rand_max);
}

static double compute_entropy (struct config *conf, const wchar_t *data, size_t datasz)
{
	size_t i;
	int ok, freq;
	double entropy = 0.0;

	ok = hcreate(datasz);
	if (!ok) {
		perror("hcreate failed");
		quit(EXIT_FAILURE);
	}

	for (i = 0; i < datasz; i++)
		update_frequencies(data[i]);

	for (i = 0; i < conf->alphabet_size; i++) {
		freq = ht_get(conf->alphabet[i]);
		if (freq)
			entropy -= freq * log2((double)freq / conf->alphabet_size);
	}

	ht_del(conf->alphabet, conf->alphabet_size);
	hdestroy();
	return entropy;
}

static double compute_best_entropy (struct config *conf, size_t pwdlen)
{
	return pwdlen * log2(conf->alphabet_size);
}

static void get_pwd_stats (struct config *conf, wchar_t *pwd, size_t pwdlen, struct pwd_stat *stats)
{
	size_t i;

	memset(stats, 0, sizeof(*stats));

	stats->entropy = compute_entropy(conf, pwd, pwdlen);

	for (i = 0; i < pwdlen; i++) {
	
		if (isutf8lower(pwd[i])) {
			stats->utf8_alpha_lower++;
		}
		else if (isutf8upper(pwd[i])) {
			stats->utf8_alpha_upper++;
		}
		else if (iswdigit(pwd[i])) {
			stats->ascii_digit++;
		}
		else if (iswlower(pwd[i])) {
			stats->ascii_alpha_lower++;
		}
		else if (iswupper(pwd[i])) {
			stats->ascii_alpha_upper++;
		}
		else if (iswspecial(pwd[i])) {
			stats->ascii_special++;
		}
		else {
			fprintf(stderr, "Problem with get_pwd_stats '%lc'\n", pwd[i]);
		}
	}
}

#define CHECK_POLICY(policy, stats, alphabet) do {                           \
	if ((policy.alphabet.min && stats.alphabet < policy.alphabet.min) || \
	    (policy.alphabet.max && stats.alphabet > policy.alphabet.max))   \
		return 0;                                                    \
} while (0)

static int check_policy (struct config *conf, wchar_t *pwd, size_t pwdlen)
{
	struct pwd_stat stat;
	struct pwd_policy policy = conf->policy;

	get_pwd_stats(conf, pwd, pwdlen, &stat);

	if (conf->opt_entropy && stat.entropy < policy.entropy.dmin)
		return 0;

	if (conf->opt_entropy && stat.entropy > policy.entropy.dmax)
		return 0;

	CHECK_POLICY(policy, stat, ascii_digit);
	CHECK_POLICY(policy, stat, ascii_alpha_lower);
	CHECK_POLICY(policy, stat, ascii_alpha_upper);
	CHECK_POLICY(policy, stat, ascii_special);
	//printf("policy.alphabet.min = %ld | policy.alphabet.max = %ld | stat.alphabet = %ld\n", policy.utf8_alpha_lower.min, policy.utf8_alpha_lower.max, stat.utf8_alpha_lower);
	CHECK_POLICY(policy, stat, utf8_alpha_lower);
	CHECK_POLICY(policy, stat, utf8_alpha_upper);

	return 1;
}

static void swap (wchar_t *a, wchar_t *b)
{
	wchar_t tmp = *a;
	*a = *b;
	*b = tmp;
}

static void shuffle (struct config *conf, wchar_t *passwd, size_t passwd_len)
{
	int i, j;

//	printf("DEBUG INIT: %ls, passwd_len = %lu\n", passwd, passwd_len);
	for (i = passwd_len - 1; i > 0; i--) {
		j = random_num(conf->urandom_fd, i);
		swap(&passwd[i], &passwd[j]);
//		printf("DEBUG LOOP: %ls\n", passwd);
//		printf("DEBUG LOOP: %lc\n", passwd[i]);
	}
}

static void shuffle_n (struct config *conf, wchar_t *passwd, size_t passwd_len)
{
	int i, shuffle_passes = conf->shuffle_passes;
	if (shuffle_passes <= 0)
		shuffle_passes = 2;

	for (i = 0; i < shuffle_passes; i++)
		shuffle(conf, passwd, passwd_len);
}

static size_t gen_sub_passwd (int urandom_fd, wchar_t *pwd, size_t pwdlen, string_t *alphabet)
{
	size_t i;
	int rand;

	if (!pwd || !pwdlen)
		return 0;

	for (i = 0; i < pwdlen; i++) {
		rand = random_num(urandom_fd, alphabet->len);
		pwd[i] = alphabet->val[rand];
	}

	return pwdlen;
}

static wchar_t *gen_passwd (struct config *conf, wchar_t *pwd, size_t pwdsz)
{
	wchar_t *ptr = pwd;

	// FIXME just avoid warning but pwdsz should be used!
	if (pwdsz) {}

	ptr += gen_sub_passwd(conf->urandom_fd, ptr, conf->policy.ascii_digit.max,       &conf->opt_ascii_digit);
	ptr += gen_sub_passwd(conf->urandom_fd, ptr, conf->policy.ascii_alpha_lower.max, &conf->opt_ascii_alpha_lower);
	ptr += gen_sub_passwd(conf->urandom_fd, ptr, conf->policy.ascii_alpha_upper.max, &conf->opt_ascii_alpha_upper);
	ptr += gen_sub_passwd(conf->urandom_fd, ptr, conf->policy.ascii_special.max,     &conf->opt_ascii_special);
	ptr += gen_sub_passwd(conf->urandom_fd, ptr, conf->policy.utf8_alpha_lower.max,  &conf->opt_utf8_alpha_lower);
	ptr += gen_sub_passwd(conf->urandom_fd, ptr, conf->policy.utf8_alpha_upper.max,  &conf->opt_utf8_alpha_upper);

	shuffle_n(conf, pwd, ptr - pwd);
	pwd[conf->policy.pwdlen] = L'\0';
	*ptr = L'\0';

	//get_pwd_stats(conf, pwd, conf->policy.pwdlen, stats);
	if (conf->opt_check_policy && !check_policy(conf, pwd, conf->policy.pwdlen))
		return NULL;

	//printf("DEBUG: BEFORE SHUFFLE: %ls\n", pwd);
	//printf("DEBUG WTFFFF: pwdsz = %lu, ptr - pwd = %lu\n", pwdsz, ptr - pwd);
	//printf("DEBUG: AFTER  SHUFFLE: %ls\n", pwd);
	return pwd;
}

static int build_alphabet_helper (struct config *conf, struct range *range, string_t *alphabet, wchar_t **output)
{
	int size = 0;

	if (range->min || range->max) {
		conf->alphabet_size += alphabet->len;
		wmemcpy(*output, alphabet->val, alphabet->len);
		*output += alphabet->len;
	}

	return size;
}

#define BUILDER(conf, charset, ptr) \
	build_alphabet_helper(conf, &conf->policy.charset, &conf->opt_##charset, ptr)

static int build_alphabet (struct config *conf)
{
	wchar_t *ptr;

	conf->alphabet = ptr = malloc(1024 * sizeof(wchar_t));
	if (!conf->alphabet) {
		perror("malloc failed");
		return -1;
	}

	BUILDER(conf, ascii_digit,       &ptr);
	BUILDER(conf, ascii_alpha_lower, &ptr);
	BUILDER(conf, ascii_alpha_upper, &ptr);
	BUILDER(conf, ascii_special,     &ptr);
	BUILDER(conf, utf8_alpha_lower,  &ptr);
	BUILDER(conf, utf8_alpha_upper,  &ptr);

	*ptr = L'\0';
	return 0;
}

static void print_passwd (struct config *conf, wchar_t *pwd, size_t pwdlen, struct pwd_stat *stat)
{
	int width, width2;
	char *lborder = "", *mborder = "\t", *rborder = "", spacer[BUFSIZ];

	if (!conf->opt_show_stats) {
		printf("%ls\n", pwd);
	}
	else {
		if (conf->opt_table) {
			lborder = "| "; mborder = " | "; rborder = " |";
		}

		width = 10 + log10(conf->policy.best_entropy);
		width2 = (conf->policy.pwdlen > 7 ? 0 : 8 - conf->policy.pwdlen);
		memset(spacer, ' ', sizeof(spacer));

		printf("%s%*.7lf%sd:%02lu a:%02lu A:%02lu s:%02lu u:%02lu U:%02lu%s%ls%.*s%s\n",
			lborder,
			width, stat->entropy,
			mborder,
			stat->ascii_digit,
			stat->ascii_alpha_lower,
			stat->ascii_alpha_upper,
			stat->ascii_special,
			stat->utf8_alpha_lower,
			stat->utf8_alpha_upper,
			mborder,
			pwd,
			width2, spacer,
			rborder);
	}

	wmemset(pwd, L'\0', pwdlen);
}

static void print_policy (struct config *conf)
{
	struct pwd_policy p = conf->policy;

	printf("Policy: d:%lu:%lu a:%lu:%lu A:%lu:%lu s:%lu:%lu u:%lu:%lu U:%lu:%lu\n",
			p.ascii_digit.min,       p.ascii_digit.max,
			p.ascii_alpha_lower.min, p.ascii_alpha_lower.max,
			p.ascii_alpha_upper.min, p.ascii_alpha_upper.max,
			p.ascii_special.min,     p.ascii_special.max,
			p.utf8_alpha_lower.min,  p.utf8_alpha_lower.max,
			p.utf8_alpha_upper.min,  p.utf8_alpha_upper.max);
}

static void check_entropy (struct config *conf)
{
	size_t pwdlen;
	wchar_t *ptr, pwd[BUFSIZ];
	struct pwd_stat stat;

	while (fgetws(pwd, sizeof(pwd), stdin)) {

		ptr = wcschr(pwd, L'\n');
		if (ptr)
			*ptr = L'\0';

		pwdlen = wcslen(pwd);
		get_pwd_stats(conf, pwd, pwdlen, &stat);
		print_passwd(conf, pwd, pwdlen, &stat);
	}
}

static size_t get_min_len (struct pwd_policy policy)
{
	return policy.ascii_digit.min
		+ policy.ascii_alpha_lower.min
		+ policy.ascii_alpha_upper.min
		+ policy.ascii_special.min
		+ policy.utf8_alpha_lower.min
		+ policy.utf8_alpha_lower.min;
}

static size_t get_max_len (struct pwd_policy policy)
{
	return policy.ascii_digit.max
		+ policy.ascii_alpha_lower.max
		+ policy.ascii_alpha_upper.max
		+ policy.ascii_special.max
		+ policy.utf8_alpha_lower.max
		+ policy.utf8_alpha_lower.max;
}

static void generate_passwords (struct config *conf)
{
	int i;
	size_t pwdlen;
	wchar_t *pwd;
	struct pwd_stat stats;

	pwdlen = get_max_len(conf->policy);
	pwd = malloc((pwdlen + 1) * sizeof(wchar_t));
	if (!pwd) {
		perror("malloc failed");
		return;
	}

	for (i = 0; i < conf->opt_passwd_count;) {

		if (gen_passwd(conf, pwd, pwdlen + 1)) {

			get_pwd_stats(conf, pwd, conf->policy.pwdlen, &stats);
			print_passwd(conf, pwd, pwdlen, &stats);
			i++;
		}
	}

	free(pwd);
}

int main (int argc, char **argv)
{
	int err;
	int pad, pad2;
	size_t pwdlen;
	double best_entropy;
	char border[BUFSIZ];
	char spacer[BUFSIZ];

	setlocale(LC_ALL, "");

	if (!argc || !argv || !*argv) {
		fprintf(stderr, "FATAL: Invalid arguments.\n");
		exit(EXIT_FAILURE);
	}

	memset(&conf, 0, sizeof(conf));
	if (!parse_opts(argc, argv, &conf)) {
		fprintf(stderr, "FATAL: Failed parsing options.\n");
		exit(EXIT_FAILURE);
	}

	err = build_alphabet(&conf);
	if (err) {
		fprintf(stderr, "FATAL: Failed building alphabet.\n");
		exit(EXIT_FAILURE);
	}

	conf.policy.best_entropy = compute_best_entropy(&conf, conf.policy.pwdlen);
	best_entropy = conf.policy.best_entropy;
	if (conf.policy.entropy.dmin == 0.0 || conf.policy.entropy.dmin == -1.0)
		conf.policy.entropy.dmin = floor(best_entropy);

	if (conf.policy.entropy.dmax == 0.0 || conf.policy.entropy.dmax == -1.0)
		conf.policy.entropy.dmax = ceil(best_entropy);

	conf.urandom_fd = open("/dev/urandom", O_RDONLY);
	if (conf.urandom_fd < 0) {
		perror("open failed");
		exit(EXIT_FAILURE);
	}

	pwdlen = conf.policy.pwdlen;

	if (conf.opt_verbose) {
		printf("\n");
		printf("Symbols: %lu\n", conf.alphabet_size);
		printf("Password length: %lu\n", pwdlen);
		print_policy(&conf);
		printf("Best entropy for charset and length: %12.8lf\n", best_entropy);
		printf("Alphabet: %ls\n", conf.alphabet);
		if (!conf.opt_table)
			printf("\n");
	}

	pad = 1 + log10(best_entropy);
	pad2 = (pwdlen > 7) ? pwdlen : 8;
	pad2 = MAX(pad2 - 8, pwdlen - 8, int);

	memset(border, '_', sizeof(border));
	memset(spacer, ' ', sizeof(spacer));

	if (conf.opt_table) {
		printf(" ___________%.*s___________________________________________%.*s\n",  pad, border, pad2, border);
		printf("|           %.*s|                               |          %.*s|\n", pad, spacer, pad2, spacer);
		printf("|   Entropy %.*s|             Stats             | Password %.*s|\n", pad, spacer, pad2, spacer);
		printf("|___________%.*s|_______________________________|__________%.*s|\n", pad, border, pad2, border);
	}

	conf.opt_check_entropy ? check_entropy(&conf) : generate_passwords(&conf);

	if (conf.opt_table) {
		printf("|___________%.*s|_______________________________|__________%.*s|\n", pad, border, pad2, border);
	}

	free(conf.alphabet);
	close(conf.urandom_fd);
	exit(EXIT_SUCCESS);
	return 0;
}

