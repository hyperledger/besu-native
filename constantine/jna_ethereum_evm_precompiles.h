#ifndef _Included_LibConstantineEIP196_Wrapper
#define _Included_LibConstantineEIP196_Wrapper

#ifdef __cplusplus
extern "C" {
#endif

// Define byte as unsigned char
typedef unsigned char byte;

/*
 * Function: ctt_eth_evm_bn254_g1add_wrapper
 * Signature: (byte*, int, const byte*, int) -> int
 */
int bn254_g1add(byte* r, int r_len, const byte* inputs, int inputs_len);

/*
 * Function: ctt_eth_evm_bn254_g1mul_wrapper
 * Signature: (byte*, int, const byte*, int) -> int
 */
int bn254_g1mul(byte* r, int r_len, const byte* inputs, int inputs_len);

/*
 * Function: ctt_eth_evm_bn254_pairingCheck_wrapper
 * Signature: (byte*, int, const byte*, int) -> int
 */
int bn254_pairingCheck(byte* r, int r_len, const byte* inputs, int inputs_len);

#ifdef __cplusplus
}
#endif

#endif /* _Included_LibConstantineEIP196_Wrapper */

