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

	fwprintf(stderr, L"Usage:\n\t%s [options]\n\n"
			"Where options might be a combination of:\n"
			"\t-h, --help                  Show this help and exit.\n"
			"\t-d, --digit <num>           Include at least <num> digits.\n"
			"\t-a, --alpha <num>           Include at least <num> lower case letters.\n"
			"\t-A, --ALPHA <num>           Include at least <num> upper case letters.\n"
			"\t-s, --special <num>         Include at least <num> special characters.\n"
			"\t-u, --utf8 <num>            Include at least <num> UTF-8 characters.\n"
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

	if (conf->policy.min_utf8) {
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
		else if (conf->policy.min_utf8) {
			ptr = wcschr(utf8, data[i]);
			if (ptr)
				freqs[ptr - conf->alphabet]++;
			else
				wprintf(L"WTFFFFF!!!\n");
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

static int check_policy (struct pwd_policy *policy, wchar_t *pwd, size_t pwdlen)
{
	size_t i;
	int digit = 0, alpha = 0, ALPHA = 0, special = 0, utf8 = 0;

	for (i = 0; i < pwdlen; i++) {

		if (isutf8(pwd[i]))
			utf8++;
		else if (iswdigit(pwd[i]))
			digit++;
		else if (iswlower(pwd[i]))
			alpha++;
		else if (iswupper(pwd[i]))
			ALPHA++;
		else if (iswspecial(pwd[i]))
			special++;
		else {
			fwprintf(stderr, L"Should never happen!: %lc\n", pwd[i]);
			exit(EXIT_FAILURE);
		}
	}

	return (digit >= policy->min_digit
			&& alpha   >= policy->min_alpha
			&& ALPHA   >= policy->min_ALPHA
			&& special >= policy->min_special
			&& utf8    >= policy->min_utf8);
}

/*
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
*/

static wchar_t *gen_passwd (struct config *conf, wchar_t *pwd, size_t pwdsz)
{
	size_t i;

	if (!pwd || !pwdsz)
		return NULL;

	for (i = 0; i < pwdsz - 1; i++)
		pwd[i] = conf->alphabet[random_num(conf->alphabet_size)];

	pwd[pwdsz - 1] = L'\0';

	//while (find_repetition(conf, pwd, pwdsz - 1))
	//	;

	if (opt_check_policy && !check_policy(&conf->policy, pwd, pwdsz - 1))
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

	if (conf->policy.min_digit) {
		conf->alphabet_size += DIGIT_CHARS_LEN;
		wmemcpy(ptr, DIGIT_CHARS, DIGIT_CHARS_LEN);
		ptr += DIGIT_CHARS_LEN;
	}

	if (conf->policy.min_alpha) {
		conf->alphabet_size += LOWER_CHARS_LEN;
		wmemcpy(ptr, LOWER_CHARS, LOWER_CHARS_LEN);
		ptr += LOWER_CHARS_LEN;
	}

	if (conf->policy.min_ALPHA) {
		conf->alphabet_size += UPPER_CHARS_LEN;
		wmemcpy(ptr, UPPER_CHARS, UPPER_CHARS_LEN);
		ptr += UPPER_CHARS_LEN;
	}

	if (conf->policy.min_special) {
		conf->alphabet_size += SPECIAL_CHARS_LEN;
		wmemcpy(ptr, SPECIAL_CHARS, SPECIAL_CHARS_LEN);
		ptr += SPECIAL_CHARS_LEN;
	}

	if (conf->policy.min_utf8) {
		conf->alphabet_size += UTF8_CHARS_LEN;
		wmemcpy(ptr, UTF8_CHARS, UTF8_CHARS_LEN);
		ptr += UTF8_CHARS_LEN;
	}

	*ptr = L'\0';
	conf->policy.best_entropy = compute_best_entropy(conf, conf->policy.pwdlen);
	return 0;
}

static void get_pwd_stats (struct config *conf, wchar_t *pwd, size_t pwdlen, struct pwd_policy *stat)
{
	size_t i;

	stat->entropy = compute_entropy(conf, pwd, pwdlen);

	for (i = 0; i < pwdlen; i++) {
	
		if (isutf8(pwd[i])) {
			stat->min_utf8++;
		}
		else if (iswdigit(pwd[i])) {
			stat->min_digit++;
		}
		else if (iswlower(pwd[i])) {
			stat->min_alpha++;
		}
		else if (iswupper(pwd[i])) {
			stat->min_ALPHA++;
		}
		else if (iswspecial(pwd[i])) {
			stat->min_special++;
		}
	}
}

static void print_passwd (wchar_t *pwd, size_t pwdlen, struct pwd_policy *stat)
{
	int padding;

	if (!opt_table) {
		wprintf(L"%ls\n", pwd);
	}
	else {
		wprintf(L"| %lf | d:%02d a:%02d A:%02d s:%02d u:%02d | %ls",
				stat->entropy,
				stat->min_digit,
				stat->min_alpha,
				stat->min_ALPHA,
				stat->min_special,
				stat->min_utf8,
				pwd);

		padding = (pwdlen > 7) ? 1 : 9 - pwdlen;
		print_char(' ', padding, L"|");
	}
}

static void check_entropy (struct config *conf)
{
	size_t pwdlen;
	wchar_t *ptr, pwd[BUFSIZ];
	struct pwd_policy stat;

	while (fgetws(pwd, sizeof(pwd), stdin)) {

		ptr = wcschr(pwd, L'\n');
		if (ptr)
			*ptr = L'\0';

		pwdlen = wcslen(pwd);

		memset(&stat, 0, sizeof(stat));
		get_pwd_stats(conf, pwd, pwdlen, &stat);
		print_passwd(pwd, pwdlen, &stat);
		wmemset(pwd, L'\0', pwdlen);
	}
}

static void generate_passwords (struct config *conf)
{
	int i;
	size_t pwdlen;
	wchar_t *pwd;
	struct pwd_policy stat;

	pwdlen = conf->policy.pwdlen;
	pwd = malloc((pwdlen + 1) * sizeof(wchar_t));
	if (!pwd) {
		wperror(L"malloc failed");
		return;
	}

	for (i = 0; i < opt_passwd_count;) {

		if (gen_passwd(conf, pwd, pwdlen + 1)) {

			memset(&stat, 0, sizeof(stat));
			get_pwd_stats(conf, pwd, pwdlen, &stat);
			if (opt_min_entropy && stat.entropy < conf->policy.min_entropy)
				continue;

			print_passwd(pwd, pwdlen, &stat);
			wmemset(pwd, L'\0', pwdlen);
			i++;
		}
	}

	free(pwd);
}

static struct config *parse_opts (int argc, char **argv, struct config *conf)
{
	int i, policy = 0;

	for (i = 1; i < argc; i++) {

		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
		}
		else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--digit")) {
			conf->policy.min_digit = strtoul(argv[i + 1], NULL, 10);
			policy++;
			i++;
		}
		else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--alpha")) {
			conf->policy.min_alpha = strtoul(argv[i + 1], NULL, 10);
			policy++;
			i++;
		}
		else if (!strcmp(argv[i], "-A") || !strcmp(argv[i], "--ALPHA")) {
			conf->policy.min_ALPHA = strtoul(argv[i + 1], NULL, 10);
			policy++;
			i++;
		}
		else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--special")) {
			conf->policy.min_special = strtoul(argv[i + 1], NULL, 10);
			policy++;
			i++;
		}
		else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--utf8")) {
			conf->policy.min_utf8 = strtoul(argv[i + 1], NULL, 10);
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
			fwprintf(stderr, L"FATAL: Invalid option: `%s'\n", argv[i]);
			usage(argv[0]);
		}
	}

	if (!conf->policy.pwdlen)
		conf->policy.pwdlen = DEFAULT_PASSWD_LEN;

	if (!policy
			&& !conf->policy.min_digit
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

int main (int argc, char **argv)
{
	size_t pad, pwdlen;
	struct config conf;
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

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		wperror(L"open failed");
		exit(EXIT_FAILURE);
	}

	pwdlen = conf.policy.pwdlen;

	best_entropy = conf.policy.best_entropy;
	if (conf.policy.min_entropy == 0.0)
		conf.policy.min_entropy = best_entropy;

	if (opt_verbose) {
		wprintf(L"\n");
		wprintf(L"Symbols: %lu\n", conf.alphabet_size);
		wprintf(L"Password length: %lu\n", pwdlen);
		wprintf(L"Best entropy for length: %lf\n", best_entropy);
		wprintf(L"Alphabet: %ls\n", conf.alphabet);
		if (!opt_table)
			wprintf(L"\n");
	}

	pad = (int)log10(best_entropy);
	wmemset(padspacer, L' ', pad);
	wmemset(padborder, L'_', pad);
	padspacer[pad] = L'\0';
	padborder[pad] = L'\0';

	pad = (pwdlen > 7) ? pwdlen : 8;
	if (opt_table) {
		wprintf(L" _________%ls_______________________________",         padborder); print_char(L'_', pad, L"");
		wprintf(L"|         %ls |                          |  ",         padspacer); print_char(L' ', pad, L"|");
		wprintf(L"|  Entropy%ls |          Stats           | Password ", padspacer); print_char(L' ', MAX(pad - 8, pwdlen - 8, int), L"|");
		wprintf(L"|_________%ls_|__________________________|__",         padborder); print_char(L'_', pad, L"|");
	}

	opt_check_entropy ? check_entropy(&conf) : generate_passwords(&conf);

	if (opt_table) {
		wprintf(L"|_________%ls_|__________________________|__", padborder); print_char(L'_', pad, L"|");
	}

	free(conf.alphabet);
	close(urandom_fd);
	exit(EXIT_SUCCESS);
	return 0;
}
