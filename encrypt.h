/* Include file for high-level encryption routines.
 *
 * Services is copyright (c) 1996-1999 Andy Church.
 *     E-mail: <achurch@dragonfire.net>
 * This program is free but copyrighted software; see the file COPYING for
 * details.
 *
 * DarkuBots es una adaptacion de Javier Fernández Viña, ZipBreake.
 * reworked and updated to modern IRCD Inspircd by reverse Jean Chevronnet.
 * E-Mail: javier@jfv.es || Web: http://jfv.es/
 *
 * Bcrypt implementation added on April 21, 2025 - replacing insecure MD5
 */

#define ENCRYPT_BCRYPT 1
#define USE_ENCRYPTION 1

/* Function prototypes */
extern int encrypt(const char *src, int len, char *dest, int size);
extern int encrypt_in_place(char *buf, int size);
extern int check_password(const char *plaintext, const char *password);
