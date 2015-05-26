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
#include <getopt.h>
#include <unistd.h>
#include <wctype.h>

#include "genpasswd.h"
#include "opts.h"

static int iswspecial (wint_t wc)
{
	return wcschr(ASCII_SPECIAL_CHARS, wc) ? 1 : 0;
}

static int isutf8lower (wint_t wc)
{
	if (iswlower(wc))
		return wcschr(UTF8_LOWER_CHARS, wc) ? 1 : 0;

	return 0;
}

static int isutf8upper (wint_t wc)
{
	if (iswupper(wc))
		return wcschr(UTF8_UPPER_CHARS, wc) ? 1 : 0;

	return 0;
}

static int random_num (struct config *conf, unsigned char rand_max)
{
	ssize_t ret;
	size_t limit;
	unsigned char rand;

	limit = UCHAR_MAX - ((UCHAR_MAX + 1) % rand_max);

	do {
		ret = read(conf->urandom_fd, &rand, sizeof(rand));
		if (ret != sizeof(rand)) {
			perror("read failed");
			close(conf->urandom_fd);
			exit(EXIT_FAILURE);
		}
	}
	while (rand > limit);

	return (rand % rand_max);
}

static double compute_entropy (struct config *conf, const wchar_t *data, size_t datasz)
{
	size_t i;
	double entropy = 0.0;
	wchar_t *ptr, *utf8 = NULL;
	char freqs[UCHAR_MAX + 1];

	memset(freqs, 0, sizeof(freqs));

	if (conf->first_utf8) {
		utf8 = wcschr(conf->alphabet, *conf->first_utf8);
		if (!utf8) {
			fprintf(stderr, "FATAL: something went wrong!\n");
			close(conf->urandom_fd);
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < datasz; i++) {

		if (data[i] < 127)
			freqs[data[i]]++;
		else if (utf8) {
			ptr = wcschr(utf8, data[i]);
			if (ptr)
				freqs[ptr - conf->alphabet]++;
			else
				fprintf(stderr, "FATAL: this should never happen!\n");
		}
	}

	for (i = 0; i < sizeof(freqs); i++) {
		if (freqs[i])
			entropy -= freqs[i] * log2((double)freqs[i] / conf->alphabet_size);
	}

	return entropy;
}

static double compute_best_entropy (struct config *conf, size_t pwdlen)
{
	return pwdlen * log2(conf->alphabet_size);
}

static void get_pwd_stats (struct config *conf, wchar_t *pwd, size_t pwdlen, struct pwd_stat *stat)
{
	size_t i;

	memset(stat, 0, sizeof(*stat));

	stat->entropy = compute_entropy(conf, pwd, pwdlen);

	for (i = 0; i < pwdlen; i++) {
	
		if (isutf8lower(pwd[i])) {
			stat->u++;
		}
		else if (isutf8upper(pwd[i])) {
			stat->U++;
		}
		else if (iswdigit(pwd[i])) {
			stat->d++;
		}
		else if (iswlower(pwd[i])) {
			stat->a++;
		}
		else if (iswupper(pwd[i])) {
			stat->A++;
		}
		else if (iswspecial(pwd[i])) {
			stat->s++;
		}
	}
}

static int check_policy (struct config *conf, wchar_t *pwd, size_t pwdlen)
{
	struct pwd_stat stat;
	struct pwd_policy policy = conf->policy;

	get_pwd_stats(conf, pwd, pwdlen, &stat);

	if (conf->opt_entropy && stat.entropy < policy.entropy.dmin)
		return 0;

	if (conf->opt_entropy && stat.entropy > policy.entropy.dmax)
		return 0;

	return ((policy.d.min <= stat.d && stat.d <= policy.d.max) &&
		(policy.a.min <= stat.a && stat.a <= policy.a.max) &&
		(policy.A.min <= stat.A && stat.A <= policy.A.max) &&
		(policy.s.min <= stat.s && stat.s <= policy.s.max) &&
		(policy.u.min <= stat.u && stat.u <= policy.u.max) &&
		(policy.U.min <= stat.U && stat.U <= policy.U.max));
}

static wchar_t *gen_passwd (struct config *conf, wchar_t *pwd, size_t pwdsz)
{
	size_t i;

	if (!pwd || !pwdsz)
		return NULL;

	for (i = 0; i < pwdsz - 1; i++)
		pwd[i] = conf->alphabet[random_num(conf, conf->alphabet_size)];

	pwd[pwdsz - 1] = L'\0';

	if (conf->opt_check_policy && !check_policy(conf, pwd, pwdsz - 1))
		return NULL;

	return pwd;
}

static int build_alphabet (struct config *conf)
{
	wchar_t *ptr;

	conf->alphabet = ptr = malloc(1024 * sizeof(wchar_t));
	if (!conf->alphabet) {
		perror("malloc failed");
		return -1;
	}

	if (conf->policy.d.min || conf->policy.d.max) {
		conf->alphabet_size += ASCII_DIGIT_CHARS_LEN;
		wmemcpy(ptr, ASCII_DIGIT_CHARS, ASCII_DIGIT_CHARS_LEN);
		ptr += ASCII_DIGIT_CHARS_LEN;
	}

	if (conf->policy.a.min || conf->policy.a.max) {
		conf->alphabet_size += ASCII_LOWER_CHARS_LEN;
		wmemcpy(ptr, ASCII_LOWER_CHARS, ASCII_LOWER_CHARS_LEN);
		ptr += ASCII_LOWER_CHARS_LEN;
	}

	if (conf->policy.A.min || conf->policy.A.max) {
		conf->alphabet_size += ASCII_UPPER_CHARS_LEN;
		wmemcpy(ptr, ASCII_UPPER_CHARS, ASCII_UPPER_CHARS_LEN);
		ptr += ASCII_UPPER_CHARS_LEN;
	}

	if (conf->policy.s.min || conf->policy.s.max) {
		conf->alphabet_size += ASCII_SPECIAL_CHARS_LEN;
		wmemcpy(ptr, ASCII_SPECIAL_CHARS, ASCII_SPECIAL_CHARS_LEN);
		ptr += ASCII_SPECIAL_CHARS_LEN;
	}

	if (conf->policy.u.min || conf->policy.u.max) {
		if (!conf->first_utf8)
			conf->first_utf8 = UTF8_LOWER_CHARS;
		conf->alphabet_size += UTF8_LOWER_CHARS_LEN;
		wmemcpy(ptr, UTF8_LOWER_CHARS, UTF8_LOWER_CHARS_LEN);
		ptr += UTF8_LOWER_CHARS_LEN;
	}

	if (conf->policy.U.min || conf->policy.U.max) {
		if (!conf->first_utf8)
			conf->first_utf8 = UTF8_UPPER_CHARS;
		conf->alphabet_size += UTF8_UPPER_CHARS_LEN;
		wmemcpy(ptr, UTF8_UPPER_CHARS, UTF8_UPPER_CHARS_LEN);
		ptr += UTF8_UPPER_CHARS_LEN;
	}

	*ptr = L'\0';
	conf->policy.best_entropy = compute_best_entropy(conf, conf->policy.pwdlen);
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
		width2 = (pwdlen > 7 ? 0 : 8 - pwdlen);
		memset(spacer, ' ', sizeof(spacer));

		printf("%s%*.8lf%sd:%02lu a:%02lu A:%02lu s:%02lu u:%02lu U:%02lu%s%ls%.*s%s\n",
			lborder,
			width, stat->entropy,
			mborder,
			stat->d, stat->a, stat->A, stat->s, stat->u, stat->U,
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
			p.d.min, p.d.max,
			p.a.min, p.a.max,
			p.A.min, p.A.max,
			p.s.min, p.s.max,
			p.u.min, p.u.max,
			p.U.min, p.U.max);
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

static void generate_passwords (struct config *conf)
{
	int i;
	size_t pwdlen;
	wchar_t *pwd;
	struct pwd_stat stat;

	pwdlen = conf->policy.pwdlen;
	pwd = malloc((pwdlen + 1) * sizeof(wchar_t));
	if (!pwd) {
		perror("malloc failed");
		return;
	}

	for (i = 0; i < conf->opt_passwd_count;) {

		if (gen_passwd(conf, pwd, pwdlen + 1)) {

			get_pwd_stats(conf, pwd, pwdlen, &stat);
			print_passwd(conf, pwd, pwdlen, &stat);
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
	struct config conf;
	double best_entropy;
	char border[BUFSIZ];
	char spacer[BUFSIZ];

	if (!argc || !argv || !*argv) {
		fprintf(stderr, "FATAL: Invalid arguments.\n");
		exit(EXIT_FAILURE);
	}

	setlocale(LC_ALL, "");
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

