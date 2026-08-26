#ifndef OUIJA_CORE_H
#define OUIJA_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Assembly cryptographic primitives --- */
void ouija_otp_xor_asm(const uint8_t *src, const uint8_t *pad, uint8_t *dst, size_t len);
int  ouija_ct_memcmp_asm(const uint8_t *a, const uint8_t *b, size_t len);
void ouija_secure_memzero_asm(void *ptr, size_t len);

/* --- C / Native security hardening functions --- */
int  ouija_harden_process(void);
int  ouija_lock_memory(void *addr, size_t len);
int  ouija_unlock_memory(void *addr, size_t len);
void *ouija_secure_alloc(size_t len);
void ouija_secure_free(void *ptr, size_t len);
int  ouija_secure_random(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* OUIJA_CORE_H */
