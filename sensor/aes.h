#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>


#ifndef bzero
#define bzero(a,b)	memset(a,'\0',b)
#endif

#ifndef _AES_H
#define _AES_H


#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

typedef struct
{
    ulong erk[64];     /* encryption round keys */
    ulong drk[64];     /* decryption round keys */
    uint nr;           /* number of rounds      */
}
aes_context;

/*
 * AES key schedule (keysize can be 128, 192 or 256)
 */
void aes_set_key( aes_context *ctx, uchar *key, uint keysize );

/*
 * AES 128-bit block encryption (ECB)
 */
void aes_encrypt( aes_context *ctx, uchar input[16], uchar output[16] );

/*
 * AES 128-bit block decryption (ECB)
 */
void aes_decrypt( aes_context *ctx, uchar input[16], uchar output[16] );

/*
 * AES-CBC encryption
 */
int  aes_cbc_encrypt( aes_context *ctx, uchar iv[16],
                      uchar *input, uchar *output, int len );

/*
 * AES-CBC decryption
 *
*/
int aes_cbc_decrypt( aes_context *ctx, uchar iv[16],
                      uchar *input, uchar *output, int len );


#endif /* aes.h */


#ifndef BASE64_H_
#define BASE64_H_
int to64frombits(unsigned char*,const unsigned char*,int);
int from64tobits(char*,const char*);
#endif /* BASE64_H_ */
