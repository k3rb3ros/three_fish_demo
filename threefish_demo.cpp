#include <iostream>
#include <stdint.h>
#include "include/threefishApi.h"

static uint64_t three_256_00_key[] = { 0L, 0L, 0L, 0L };
static uint64_t three_256_00_input[] = { 0L, 0L, 0L, 0L };
static uint64_t three_256_00_tweak[] = { 0L, 0L };

int main(void)
{
	ThreefishKey_t keyCtx;
	uint64_t cipher[Threefish256/64];
	uint64_t plain[Threefish256/64];
	threefishSetKey(&keyCtx, Threefish256, three_256_00_key, three_256_00_tweak);	

	return 0;
}
