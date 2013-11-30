#include <iostream>
#include <stdint.h>
#include <string.h>
#include "include/skeinApi.h"
#include "include/threefishApi.h"

using namespace std;

const static uint8_t hex_lookup[] { '0', '1', '2','3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
const static uint8_t mac_key[] { 'S', 's', 'h', 'h', 'd', 'o', 'n' , '`', 't', 't', 'e', 'l', 'l' };
static uint64_t three_256_key[] = { 0L, 0L, 0L, 0L };
static uint64_t three_512_key[] = { 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L };
static uint64_t three_1024_key[] = { 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L };
static uint64_t threefish_tweak[] = { 0xB7E151628AED2A6AL, 0x243F6A8885A308D3L };

void ClearBlock(uint8_t* block, uint64_t size) //Zero fill the block passed into the function
{
	for(uint8_t i=0; i<(size); i++) block[i] = 0;
}

void PrintBlock(uint8_t* block, uint64_t size)
{
	for(uint64_t i=0; i<size; i++)
	{
		cout << "/" << (int)block[i];
	}
}

void PrintHash(uint8_t* hash, uint16_t len)
{
	//alloc space for the hex buffer (2x the binary byte buffer)
	uint8_t* hex = (uint8_t*)calloc(2*len, sizeof(uint8_t));
	
	//C style lookup the hash (using bitwise operations on each nibble) to get the hex value
	for(int i=0, k=0; i<len; i++)
	{
		hex[k++] = hex_lookup[hash[i] >> 4];
		hex[k++] = hex_lookup[hash[i] & 0x0F];
	}
	//output it
	printf("%s", hex);
	//free the memory we allocated
	free(hex); 
}

void DemoThreefish256(uint8_t* txt)
{
	//Declare our key/state structure
	ThreefishKey_t key_256;

	//Init the cipher 	
	threefishSetKey(&key_256, Threefish256, three_256_key, threefish_tweak);

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
	threefishEncryptBlockWords(&key_256, plain_block, cipher_block);
	threefishDecryptBlockWords(&key_256, cipher_block, decrypt_block);

	//Copy the results to Display buffers
	memcpy(disp_ciph, cipher_block, Threefish256/8);
	memcpy(disp_decr, decrypt_block, Threefish256/8);
	memcpy(disp_plain, plain_block, Threefish256/8);
	
	//Print the results for the user to see
	printf("Threefish256 plaintext: [%s] ciphertext: [", disp_plain);
	//PrintBlock(disp_ciph, Threefish256/8);
	PrintHash((uint8_t*)cipher_block, Threefish256/8);	

	printf("] decryptedtext: [%s]\n\n", disp_decr);
}

void DemoThreefish512(uint8_t* txt)
{
	//Declare our key/state structure
	ThreefishKey_t key_512;
	
	//Set up the cipher
	threefishSetKey(&key_512, Threefish512, three_512_key, threefish_tweak);

	// Declare our blocks
	uint64_t cipher_block[Threefish512/64];
	uint64_t decrypt_block[Threefish512/64];
	uint64_t plain_block[Threefish512/64];
	//Same buffer but 1 char longer to append /0
	uint8_t disp_ciph[(Threefish512/8)+1];	
	uint8_t disp_decr[(Threefish512/8)+1];	
	uint8_t disp_plain[(Threefish512/8)+1];	

	//Zero fill the buffers
	ClearBlock((uint8_t*)cipher_block, Threefish512/8);
	ClearBlock((uint8_t*)decrypt_block, Threefish512/8);
	ClearBlock((uint8_t*)plain_block, Threefish512/8);
	ClearBlock((uint8_t*)disp_ciph, (Threefish512/8)+1);
	ClearBlock((uint8_t*)disp_decr, (Threefish512/8)+1);
	ClearBlock((uint8_t*)disp_plain, (Threefish512/8)+1);

	//Put the txt in plaintext buffer
	memcpy(plain_block, txt, strlen((char*)txt));
	//Encrypt and decrypt the text putting the result of decryption in new buffer
	threefishEncryptBlockWords(&key_512, plain_block, cipher_block);
	threefishDecryptBlockWords(&key_512, cipher_block, decrypt_block);

	//Copy the results to Display buffers
	memcpy(disp_ciph, cipher_block, Threefish512/8);
	memcpy(disp_decr, decrypt_block, Threefish512/8);
	memcpy(disp_plain, plain_block, Threefish512/8);

	//Print the results for the user to see
	printf("Threefish512 plaintext: [%s] ciphertext: [", disp_plain);
	//PrintBlock(disp_ciph, Threefish512/8);
	PrintHash((uint8_t*)cipher_block, Threefish512/8);	
	printf("] decryptedtext: [%s]\n\n", disp_decr);
}

void DemoThreefish1024(uint8_t* txt)
{
	//Declare our key/state structure
	ThreefishKey_t key_1024;

	//Set up the cipher
	threefishSetKey(&key_1024, Threefish1024, three_1024_key, threefish_tweak);
        //Declare our blocks
        uint64_t cipher_block[Threefish1024/64];
        uint64_t decrypt_block[Threefish1024/64];
        uint64_t plain_block[Threefish1024/64];
        //Same buffer but 1 char longer to append /0
        uint8_t disp_ciph[(Threefish1024/8)+1];
        uint8_t disp_decr[(Threefish1024/8)+1];
        uint8_t disp_plain[(Threefish1024/8)+1];

        //Zero fill the buffers
        ClearBlock((uint8_t*)cipher_block, Threefish1024/8);
        ClearBlock((uint8_t*)decrypt_block, Threefish1024/8);
        ClearBlock((uint8_t*)plain_block, Threefish1024/8);
        ClearBlock((uint8_t*)disp_ciph, (Threefish1024/8)+1);
        ClearBlock((uint8_t*)disp_decr, (Threefish1024/8)+1);
        ClearBlock((uint8_t*)disp_plain, (Threefish1024/8)+1);

        //Put the txt in plaintext buffer
        memcpy(plain_block, txt, strlen((char*)txt));
        //Encrypt and decrypt the text putting the result of decryption in new buffer
        threefishEncryptBlockWords(&key_1024, plain_block, cipher_block);
        threefishDecryptBlockWords(&key_1024, cipher_block, decrypt_block);

        //Copy the results to Display buffers
        memcpy(disp_ciph, cipher_block, Threefish1024/8);
        memcpy(disp_decr, decrypt_block, Threefish1024/8);
        memcpy(disp_plain, plain_block, Threefish1024/8);

	//Print the results for the user to see
	printf("Threefish1024 plaintext: [%s] ciphertext: [", disp_plain);
	//PrintBlock(disp_ciph, Threefish512/8);
	PrintHash((uint8_t*)cipher_block, Threefish512/8);	
	printf("] decryptedtext: [%s]\n\n", disp_decr);
}

uint8_t* SkeinHash(uint8_t* message, SkeinSize_t state_size, size_t hashBitLen)
{
	//allocate storage for the hash
	uint8_t* hash = (uint8_t*)calloc((hashBitLen+8-1)/8, sizeof(uint8_t));

	//Declare the internal structures for Skein
	SkeinCtx skein_state;
	
	//Prepare the Skein context
	skeinCtxPrepare(&skein_state, state_size);

	//Init Skein and tell it how big the hash should be in bits
	skeinInit(&skein_state, hashBitLen);

	//Run skein on the message
	skeinUpdate(&skein_state, message, strlen((char*)message));

	//Get the hash
	skeinFinal(&skein_state, hash);

	return hash;
}

uint8_t* SkeinMAC(uint8_t* message, SkeinSize_t state_size, uint32_t digest_length)
{
	//allocate storeage for the MAC
	uint8_t* mac = (uint8_t*)calloc((digest_length+8-1)/8, sizeof(uint8_t));
	
	//Declare the internal structures for Skein
	SkeinCtx skein_state;

	//Prepare the Skein context
	skeinCtxPrepare(&skein_state, state_size);

	//Init Skein (in MAC mode)  and tell it how big the hash should be in bits
	skeinMacInit(&skein_state, mac_key, 13 ,digest_length);
	
	//Run skein on the message
	skeinUpdate(&skein_state, message, strlen((char*)message));

	//Get the MAC
	skeinFinal(&skein_state, mac);

	//output the MAC to be used
	return mac;
}

int main(int argc, char** argv)
{	
	uint8_t* hash = NULL;
	uint8_t* mac = NULL;
	uint8_t text[64];
	
	//Zerofill text
	ClearBlock(text, 64);

	//if the program is called with no text entered
	if(argc == 1)strncpy((char*)text, "Oh look some shady text", 23);
		
	else if(argc == 2 && strlen(argv[1]) < (256/8)) strncpy((char*)text, argv[1], strlen(argv[1]));
	
	else 
	{
		cout << "Usage: threefish_skein_demo <OPTIONAL> text" << endl;
		return 1;
	}
	//Demo the block ciphers
	DemoThreefish256(text);
	DemoThreefish512(text);
	DemoThreefish1024(text);

	hash = SkeinHash(text, Skein256, Skein256);
	printf("Skein256 hash: [");
	PrintHash(hash, Threefish256/8);
	printf("]\n\n");
	free(hash);
	
	hash = SkeinHash(text, Skein512, Skein512);
	printf("Skein512 hash: [");
        PrintHash(hash, Threefish512/8);
        printf("]\n\n");
	free(hash);
	
	hash = SkeinHash(text, Skein1024, Skein1024);
	printf("Skein1024 hash: [");
        PrintHash(hash, Threefish1024/8);
        printf("]\n\n");
	free(hash);
		
	mac = SkeinMAC(text, Skein256, 4);
	printf("Skein256 mac of previous text: [");
	PrintHash(mac, 4);
	printf("]\n\n");
	free(mac);

	mac = SkeinMAC(text, Skein512, 4);
	printf("Skein512 mac of previous text: [");
	PrintHash(mac, 4);
	printf("]\n\n");
	
	mac = SkeinMAC(text, Skein1024, 4);
	printf("Skein1024 mac of previous text: [");
	PrintHash(mac, 4);
	printf("]\n\n");

	return 0;
}
