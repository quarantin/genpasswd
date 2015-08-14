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
#ifndef GENPASSWD_H
#define GENPASSWD_H

#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
 
#define PROG_NAME "passwdgen"
 
#define DEFAULT_PASSWD_LEN 16
#define DEFAULT_PASSWD_SIZE (DEFAULT_PASSWD_LEN + 1)
#define DEFAULT_PASSWD_COUNT 32

#define MIN(x, y, t) ((t)(x) > (t)(y) ? (t)(y) : (t)(x))
#define MAX(x, y, t) ((t)(x) < (t)(y) ? (t)(y) : (t)(x))

#define LENGTH(sizeof_x) ((sizeof_x - sizeof(wchar_t)) / sizeof(wchar_t))
 
#define ASCII_DIGIT_CHARS L"0123456789"
#define ASCII_DIGIT_CHARS_LEN LENGTH(sizeof(ASCII_DIGIT_CHARS))
 
#define ASCII_ALPHA_LOWER_CHARS L"abcdefghijklmnopqrstuvwxyz"
#define ASCII_ALPHA_LOWER_CHARS_LEN LENGTH(sizeof(ASCII_ALPHA_LOWER_CHARS))
 
#define ASCII_ALPHA_UPPER_CHARS L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ASCII_ALPHA_UPPER_CHARS_LEN LENGTH(sizeof(ASCII_ALPHA_UPPER_CHARS))
 
#define ASCII_SPECIAL_CHARS L" !#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\""
#define ASCII_SPECIAL_CHARS_LEN LENGTH(sizeof(ASCII_SPECIAL_CHARS))

#define UTF8_ALPHA_LOWER_CHARS L"àáâãäåæçðèéêëœìíîïñòóôõöøŧþùúûüýŷÿ"
#define UTF8_ALPHA_LOWER_CHARS_LEN LENGTH(sizeof(UTF8_ALPHA_LOWER_CHARS))

#define UTF8_ALPHA_UPPER_CHARS L"ÀÁÂÃÄÅÆÇÐÈÉÊËŒÌÍÎÏÑÒÓÔÕÖØŦÞÙÚÛÜÝŶŸ"
#define UTF8_ALPHA_UPPER_CHARS_LEN LENGTH(sizeof(UTF8_ALPHA_UPPER_CHARS))

#define UTF8_SPECIAL_CHARS L"×÷ß€" // TODO
#define UTF8_SPECIAL_CHARS_LEN LENGTH(sizeof(UTF8_SPECIAL_CHARS))

typedef struct {
	size_t len;
	wchar_t *val;
} string_t;

struct range {
	size_t min;
	size_t max;
	double dmin;
	double dmax;
};

struct pwd_stat {
	size_t ascii_digit;
	size_t ascii_alpha_lower;
	size_t ascii_alpha_upper;
	size_t ascii_special;
	size_t utf8_alpha_lower;
	size_t utf8_alpha_upper;
	size_t utf8_special;
	double entropy;
};

struct pwd_policy {
	struct range ascii_digit;
	struct range ascii_alpha_lower;
	struct range ascii_alpha_upper;
	struct range ascii_special;
	struct range utf8_alpha_lower;
	struct range utf8_alpha_upper;
	struct range utf8_special;
	struct range entropy;
	double best_entropy;
	size_t pwdlen;
};

struct config {
	int urandom_fd;
	wchar_t *alphabet;
	wchar_t *first_utf8;
	size_t alphabet_size;
	struct pwd_policy policy;
	int shuffle_passes;
	string_t opt_ascii_digit;
	string_t opt_ascii_alpha_lower;
	string_t opt_ascii_alpha_upper;
	string_t opt_ascii_special;
	string_t opt_utf8_digit;
	string_t opt_utf8_alpha_lower;
	string_t opt_utf8_alpha_upper;
	string_t opt_utf8_special;

	int opt_check_entropy;
	int opt_check_policy;
	int opt_show_stats;
	int opt_entropy;
	int opt_passwd_count;
	int opt_table;
	int opt_header;
	int opt_verbose;
};

#endif /* GENPASSWD_H */

