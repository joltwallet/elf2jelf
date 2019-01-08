#ifndef __JOLT_TYPES_H__
#define __JOLT_TYPES_H__

/* Errors Nano Lib functions can return */
typedef enum jolt_err_t{
    E_SUCCESS=0,
    E_FAILURE,
    E_NOT_IMPLEMENTED,
    E_END_OF_FUNCTION,
    E_INSUFFICIENT_BUF,
    E_INVALID_ADDRESS,
    E_UNDEFINED_BLOCK_TYPE,
    E_INVALID_STRENGTH,
    E_INVALID_MNEMONIC,
    E_INVALID_MNEMONIC_LEN,
    E_INVALID_CHECKSUM,
    E_UNABLE_ALLOCATE_MEM,
    E_NETWORK,
} jolt_err_t;

/* Generic write-esque function */
typedef int (*write_fun_t)(const void *, size_t, size_t, void *);

/* Generic Definitions */
#define CONFIDENTIAL // Way to mark sensitive data
#define NUM_OF(x) (sizeof (x) / sizeof (*x))

#define BIN_64 8
#define BIN_128 16
#define BIN_256 32
#define BIN_512 64

#define HEX_64 (2*BIN_64+1)
#define HEX_128 (2*BIN_128+1)
#define HEX_256 (2*BIN_256+1)
#define HEX_512 (2*BIN_512+1)

/* typedefs */
// I think I can get rid of the 64's
typedef unsigned char bin64_t[BIN_64];
typedef char hex64_t[HEX_64];

typedef unsigned char uint128_t[BIN_128];
typedef char hex128_t[HEX_128];

typedef unsigned char uint256_t[BIN_256];
typedef char hex256_t[HEX_256];

typedef unsigned char uint512_t[BIN_512];
typedef char hex512_t[HEX_512];


#endif
