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
 
#define PROG_NAME "passwdgen"
 
#define DEFAULT_PASSWD_LEN 16
#define DEFAULT_PASSWD_SIZE (DEFAULT_PASSWD_LEN + 1)
#define DEFAULT_PASSWD_COUNT 64

#define LENGTH(x) (sizeof(x) - 1)
#define MAX(x, y) ((x) < (y) ? (y) : (x))
 
#define DIGIT_CHARS "0123456789"
#define DIGIT_CHARS_LEN LENGTH(DIGIT_CHARS)
 
#define LOWER_CHARS "abcdefghijklmnopqrstuvwxyz"
#define LOWER_CHARS_LEN LENGTH(LOWER_CHARS)
 
#define UPPER_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define UPPER_CHARS_LEN LENGTH(UPPER_CHARS)
 
#define SPECIAL_CHARS "!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\""
#define SPECIAL_CHARS_LEN LENGTH(SPECIAL_CHARS)

struct pwd_policy {
	int min_digit;
	int min_alpha;
	int min_ALPHA;
	int min_special;
	double min_entropy;
	size_t pwdlen;
};

struct config {
	struct pwd_policy policy;
	unsigned char *alphabet;
	size_t alphabet_size;
};

#endif /* GENPASSWD_H */

