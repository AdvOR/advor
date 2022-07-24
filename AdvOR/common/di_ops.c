/* Copyright (c) 2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file di_ops.c
 * \brief Functions for data-independent operations.
 **/

#include "orconfig.h"
#include "di_ops.h"

/**
 * Timing-safe version of memcmp.  As memcmp, compare the <b>sz</b> bytes at
 * <b>a</b> with the <b>sz</b> bytes at <b>b</b>, and return less than 0 if
 * the bytes at <b>a</b> lexically precede those at <b>b</b>, 0 if the byte
 * ranges are equal, and greater than zero if the bytes at <b>a</b> lexically
 * follow those at <b>b</b>.
 *
 * This implementation differs from memcmp in that its timing behavior is not
 * data-dependent: it should return in the same amount of time regardless of
 * the contents of <b>a</b> and <b>b</b>.
 */
int
tor_memcmp(const void *a, const void *b, size_t len)
{
  const uint8_t *x = a;
  const uint8_t *y = b;
  size_t i = len;
  int retval = 0;

  /* This loop goes from the end of the arrays to the start.  At the
   * start of every iteration, before we decrement i, we have set
   * "retval" equal to the result of memcmp(a+i,b+i,len-i).  During the
   * loop, we update retval by leaving it unchanged if x[i]==y[i] and
   * setting it to x[i]-y[i] if x[i]!= y[i].
   *
   * The following assumes we are on a system with two's-complement
   * arithmetic.  We check for this at configure-time with the check
   * that sets USING_TWOS_COMPLEMENT.  If we aren't two's complement, then
   * torint.h will stop compilation with an error.
   */
  while (i--) {
    int v1 = x[i];
    int v2 = y[i];
    int equal_p = v1 ^ v2;

    /* The following sets bits 8 and above of equal_p to 'equal_p ==
     * 0', and thus to v1 == v2.  (To see this, note that if v1 ==
     * v2, then v1^v2 == equal_p == 0, so equal_p-1 == -1, which is the
     * same as ~0 on a two's-complement machine.  Then note that if
     * v1 != v2, then 0 < v1 ^ v2 < 256, so 0 <= equal_p - 1 < 255.)
     */
    --equal_p;

    equal_p >>= 8;
    /* Thanks to (sign-preserving) arithmetic shift, equal_p is now
     * equal to -(v1 == v2), which is exactly what we need below.
     * (Since we're assuming two's-complement arithmetic, -1 is the
     * same as ~0 (all bits set).)
     *
     * (The result of an arithmetic shift on a negative value is
     * actually implementation-defined in standard C.  So how do we
     * get away with assuming it?  Easy.  We check.) */
#if ((-60 >> 8) != -1)
#error "According to cpp, right-shift doesn't perform sign-extension."
#endif

    /* If v1 == v2, equal_p is ~0, so this will leave retval
     * unchanged; otherwise, equal_p is 0, so this will zero it. */
    retval &= equal_p;

    /* If v1 == v2, then this adds 0, and leaves retval unchanged.
     * Otherwise, we just zeroed retval, so this sets it to v1 - v2. */
    retval += (v1 - v2);

    /* There.  Now retval is equal to its previous value if v1 == v2, and
     * equal to v1 - v2 if v1 != v2. */
  }

  return retval;
}

/**
 * Timing-safe memory comparison.  Return true if the <b>sz</b> bytes at
 * <b>a</b> are the same as the <b>sz</b> bytes at <b>b</b>, and 0 otherwise.
 *
 * This implementation differs from !memcmp(a,b,sz) in that its timing
 * behavior is not data-dependent: it should return in the same amount of time
 * regardless of the contents of <b>a</b> and <b>b</b>.  It differs from
 * !tor_memcmp(a,b,sz) by being faster.
 */
int
tor_memeq(const void *a, const void *b, size_t sz)
{
  /* Treat a and b as byte ranges. */
  const uint8_t *ba = a, *bb = b;
  uint32_t any_difference = 0;
  while (sz--) {
    /* Set byte_diff to all of those bits that are different in *ba and *bb,
     * and advance both ba and bb. */
    const uint8_t byte_diff = *ba++ ^ *bb++;

    /* Set bits in any_difference if they are set in byte_diff. */
    any_difference |= byte_diff;
  }

  /* Now any_difference is 0 if there are no bits different between
   * a and b, and is nonzero if there are bits different between a
   * and b.  Now for paranoia's sake, let's convert it to 0 or 1.
   *
   * (If we say "!any_difference", the compiler might get smart enough
   * to optimize-out our data-independence stuff above.)
   *
   * To unpack:
   *
   * If any_difference == 0:
   *            any_difference - 1 == ~0
   *     (any_difference - 1) >> 8 == 0x00ffffff
   *     1 & ((any_difference - 1) >> 8) == 1
   *
   * If any_difference != 0:
   *            0 < any_difference < 256, so
   *            0 < any_difference - 1 < 255
   *            (any_difference - 1) >> 8 == 0
   *            1 & ((any_difference - 1) >> 8) == 0
   */

  return 1 & ((any_difference - 1) >> 8);
}

