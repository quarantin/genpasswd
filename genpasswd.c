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

int urandom_fd;

struct config conf;

static int iswspecial (wint_t wc)
{
	return wcschr(SPECIAL_CHARS, wc) ? 1 : 0;
}

static int isutf8 (wint_t wc)
{
	return wcschr(UTF8_CHARS, wc) ? 1 : 0;
}

static void wperror (wchar_t *msg)
{
	fwprintf(stderr, L"%ls: %s\n", msg, strerror(errno));
}

static void print_char (wchar_t c, size_t count, wchar_t *eol)
{
	size_t i;

	for (i = 0; i < count; i++)
		putwchar(c);

	wprintf(L"%ls\n", eol);
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
			wperror(L"read failed");
			close(urandom_fd);
			exit(EXIT_FAILURE);
		}
	}
	while (rand > limit);

	return (rand % rand_max);
}

static double compute_entropy (struct config *conf, const wchar_t *data, size_t datasz)
{
	size_t i;
	double proba, entropy = 0.0;
	wchar_t *ptr, *utf8, freqs[UCHAR_MAX + 1];

	wmemset(freqs, L'\0', sizeof(freqs) / sizeof(wchar_t));

	if (conf->policy.u.min) {
		utf8 = wcschr(conf->alphabet, *UTF8_CHARS);
		if (!utf8) {
			fwprintf(stderr, L"FATAL: something went wrong!\n");
			close(urandom_fd);
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < datasz; i++) {

		if (data[i] < 127)
			freqs[data[i]]++;
		else if (conf->policy.u.min) {
			ptr = wcschr(utf8, data[i]);
			if (ptr)
				freqs[ptr - conf->alphabet]++;
			else
				wprintf(L"FATAL: this should never happen!\n");
		}
	}

	for (i = 0; i < sizeof(freqs) / sizeof(wchar_t); i++) {
		if (freqs[i]) {
			proba = (double)freqs[i] / conf->alphabet_size;
			entropy -= proba * log2(proba);
		}
	}

	return entropy * 100;
}

static double compute_best_entropy (struct config *conf, size_t pwdlen)
{
	size_t i;
	double entropy;
	wchar_t *pwd;

	pwd = malloc((pwdlen + 1) * sizeof(wint_t));
	if (!pwd) {
		wperror(L"malloc failed");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < pwdlen; i++)
		pwd[i] = conf->alphabet[i % conf->alphabet_size];

	pwd[pwdlen] = L'\0';
	entropy = compute_entropy(conf, pwd, pwdlen);
	free(pwd);
	return entropy;
}

static void get_pwd_stats (struct config *conf, wchar_t *pwd, size_t pwdlen, struct pwd_stat *stat)
{
	size_t i;

	memset(stat, 0, sizeof(*stat));

	stat->entropy = compute_entropy(conf, pwd, pwdlen);

	for (i = 0; i < pwdlen; i++) {
	
		if (isutf8(pwd[i])) {
			stat->u++;
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
	return ((policy.d.min <= stat.d && stat.d <= policy.d.max) &&
		(policy.a.min <= stat.a && stat.a <= policy.a.max) &&
		(policy.A.min <= stat.A && stat.A <= policy.A.max) &&
		(policy.s.min <= stat.s && stat.s <= policy.s.max) &&
		(policy.u.min <= stat.u && stat.u <= policy.u.max));
}

static wchar_t *gen_passwd (struct config *conf, wchar_t *pwd, size_t pwdsz)
{
	size_t i;

	if (!pwd || !pwdsz)
		return NULL;

	for (i = 0; i < pwdsz - 1; i++)
		pwd[i] = conf->alphabet[random_num(conf->alphabet_size)];

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
		wperror(L"malloc failed");
		return -1;
	}

	if (conf->policy.d.min || conf->policy.d.max) {
		conf->alphabet_size += DIGIT_CHARS_LEN;
		wmemcpy(ptr, DIGIT_CHARS, DIGIT_CHARS_LEN);
		ptr += DIGIT_CHARS_LEN;
	}

	if (conf->policy.a.min || conf->policy.a.max) {
		conf->alphabet_size += LOWER_CHARS_LEN;
		wmemcpy(ptr, LOWER_CHARS, LOWER_CHARS_LEN);
		ptr += LOWER_CHARS_LEN;
	}

	if (conf->policy.A.min || conf->policy.A.max) {
		conf->alphabet_size += UPPER_CHARS_LEN;
		wmemcpy(ptr, UPPER_CHARS, UPPER_CHARS_LEN);
		ptr += UPPER_CHARS_LEN;
	}

	if (conf->policy.s.min || conf->policy.s.max) {
		conf->alphabet_size += SPECIAL_CHARS_LEN;
		wmemcpy(ptr, SPECIAL_CHARS, SPECIAL_CHARS_LEN);
		ptr += SPECIAL_CHARS_LEN;
	}

	if (conf->policy.u.min || conf->policy.u.max) {
		conf->alphabet_size += UTF8_CHARS_LEN;
		wmemcpy(ptr, UTF8_CHARS, UTF8_CHARS_LEN);
		ptr += UTF8_CHARS_LEN;
	}

	*ptr = L'\0';
	conf->policy.best_entropy = compute_best_entropy(conf, conf->policy.pwdlen);
	return 0;
}

static void print_passwd (struct config *conf, wchar_t *pwd, size_t pwdlen, struct pwd_stat *stat)
{
	int padding;

	if (!conf->opt_table) {
		wprintf(L"%ls\n", pwd);
	}
	else {
		wprintf(L"| %lf | d:%02d a:%02d A:%02d s:%02d u:%02d | %ls",
				stat->entropy,
				stat->d,
				stat->a,
				stat->A,
				stat->s,
				stat->u,
				pwd);

		padding = (pwdlen > 7) ? 1 : 9 - pwdlen;
		print_char(' ', padding, L"|");
	}
}

static void print_policy (struct config *conf)
{
	struct pwd_policy policy = conf->policy;

	wprintf(L"Policy:\n");
	wprintf(L"\td: %u:%u\n", policy.d.min, policy.d.max);
	wprintf(L"\ta: %u:%u\n", policy.a.min, policy.a.max);
	wprintf(L"\tA: %u:%u\n", policy.A.min, policy.A.max);
	wprintf(L"\ts: %u:%u\n", policy.s.min, policy.s.max);
	wprintf(L"\tu: %u:%u\n", policy.u.min, policy.u.max);
	wprintf(L"\n");
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
		wmemset(pwd, L'\0', pwdlen);
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
		wperror(L"malloc failed");
		return;
	}

	for (i = 0; i < conf->opt_passwd_count;) {

		if (gen_passwd(conf, pwd, pwdlen + 1)) {

			get_pwd_stats(conf, pwd, pwdlen, &stat);
			if (conf->opt_min_entropy && stat.entropy < conf->policy.min_entropy)
				continue;

			print_passwd(conf, pwd, pwdlen, &stat);
			wmemset(pwd, L'\0', pwdlen);
			i++;
		}
	}

	free(pwd);
}

int main (int argc, char **argv)
{
	int err;
	size_t pad, pwdlen;
	double best_entropy;
	wchar_t padspacer[32];
	wchar_t padborder[32];

	if (!argc || !argv || !*argv) {
		fwprintf(stderr, L"FATAL: Invalid arguments.\n");
		exit(EXIT_FAILURE);
	}

	setlocale(LC_ALL, "");
	memset(&conf, 0, sizeof(conf));
	if (!parse_opts(argc, argv, &conf)) {
		fwprintf(stderr, L"FATAL: Failed parsing options.\n");
		exit(EXIT_FAILURE);
	}

	err = build_alphabet(&conf);
	if (err) {
		fwprintf(stderr, L"FATAL: Failed building alphabet.\n");
		exit(EXIT_FAILURE);
	}

	urandom_fd = conf.urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		wperror(L"open failed");
		exit(EXIT_FAILURE);
	}

	pwdlen = conf.policy.pwdlen;

	best_entropy = conf.policy.best_entropy;
	if (conf.policy.min_entropy == 0.0)
		conf.policy.min_entropy = best_entropy;

	if (conf.opt_verbose) {
		wprintf(L"\n");
		wprintf(L"Symbols: %lu\n", conf.alphabet_size);
		wprintf(L"Password length: %lu\n", pwdlen);
		wprintf(L"Best entropy for length: %lf\n", best_entropy);
		wprintf(L"Alphabet: %ls\n", conf.alphabet);
		print_policy(&conf);
		if (!conf.opt_table)
			wprintf(L"\n");
	}

	pad = (int)log10(best_entropy);
	wmemset(padspacer, L' ', pad);
	wmemset(padborder, L'_', pad);
	padspacer[pad] = L'\0';
	padborder[pad] = L'\0';

	pad = (pwdlen > 7) ? pwdlen : 8;
	if (conf.opt_table) {
		wprintf(L" _________%ls_______________________________",         padborder); print_char(L'_', pad, L"");
		wprintf(L"|         %ls |                          |  ",         padspacer); print_char(L' ', pad, L"|");
		wprintf(L"|  Entropy%ls |          Stats           | Password ", padspacer); print_char(L' ', MAX(pad - 8, pwdlen - 8, int), L"|");
		wprintf(L"|_________%ls_|__________________________|__",         padborder); print_char(L'_', pad, L"|");
	}

	conf.opt_check_entropy ? check_entropy(&conf) : generate_passwords(&conf);

	if (conf.opt_table) {
		wprintf(L"|_________%ls_|__________________________|__", padborder); print_char(L'_', pad, L"|");
	}

	free(conf.alphabet);
	close(urandom_fd);
	exit(EXIT_SUCCESS);
	return 0;
}

