#include <iostream>
#include <stdint.h>
#include <string.h>
#include "include/threefishApi.h"

using namespace std;

static uint64_t three_256_key[] = { 0x1234L, 0x5678L, 0x91011L, 0x12131415L };
static uint64_t three_256_tweak[] = { 0xB7E151628AED2A6AL, 0x243F6A8885A308D3L };

void ClearBlock(uint8_t* block, uint64_t size) //Zero fill the block passed into the function
{
	for(uint8_t i=0; i<(size); i++) block[i] = 0;
}

void DemoThreefish256(uint8_t* txt, ThreefishKey_t* key)
{
	//Plaintext Ciphertext and Decrypttext(plaintext again to show decrypt worked)
	uint64_t cipher_block[Threefish256/64];
	uint64_t decrypt_block[Threefish256/64];
	uint64_t plain_block[Threefish256/64];
	//Same buffer but 1 char longer to append /0
	uint8_t disp_ciph[(Threefish256/8)+1];	
	uint8_t disp_decr[(Threefish256/8)+1];	
	uint8_t disp_plain[(Threefish256/8)+1];	

	//Zero fill the buffers
	ClearBlock((uint8_t*)cipher_block, Threefish256/8);
	ClearBlock((uint8_t*)decrypt_block, Threefish256/8);
	ClearBlock((uint8_t*)plain_block, Threefish256/8);
	ClearBlock((uint8_t*)disp_ciph, (Threefish256/8)+1);
	ClearBlock((uint8_t*)disp_decr, (Threefish256/8)+1);
	ClearBlock((uint8_t*)disp_plain, (Threefish256/8)+1);
	
	//Put the txt in plaintext buffer
	memcpy(plain_block, txt, strlen((char*)txt));

	//Encrypt and decrypt the text putting the result of decryption in new buffer
	threefishEncryptBlockWords(key, plain_block, cipher_block);
	threefishDecryptBlockWords(key, cipher_block, decrypt_block);

	//Copy the results to Display buffers
	memcpy(disp_ciph, cipher_block, Threefish256/8);
	memcpy(disp_decr, decrypt_block, Threefish256/8);
	memcpy(disp_plain, plain_block, Threefish256/8);
	
	//Print theresults for the user to see
	printf("Threefish256 plaintext: [%s] ciphertext: [%s] decrypted text: [%s]\n" , disp_plain, disp_ciph, disp_decr);
}

int main(void)
{
	ThreefishKey_t key_256;
	//ThreefishKey_t key_512;
	//ThreefishKey_t key_1024;
	
	uint8_t text[64];
	
	//Zerofill text
	ClearBlock(text, 64);
	strncpy((char*)text, "Oh look some shady text", 23);
		
	threefishSetKey(&key_256, Threefish256, three_256_key, three_256_tweak);         //Set up the cipher
	
	DemoThreefish256(text, &key_256);

	return 0;
}
