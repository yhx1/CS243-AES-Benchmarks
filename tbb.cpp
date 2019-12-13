#include <iostream>
#include <time.h>
#include "AES.h"
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#include <tbb/tbb_stddef.h>
#include <tbb/task_scheduler_init.h>


const unsigned int PLAIN_POOL_NUM_BYTES = 256;

const long INPUT_SIZE = 10485760 / 16;


const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

unsigned char plain[PLAIN_POOL_NUM_BYTES]; // = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext
unsigned int outLen = 0;  // out param - bytes in сiphertext

unsigned char * in_buffer;
unsigned char * out_buffer;

void init2()
{
	for (int i=0; i < PLAIN_POOL_NUM_BYTES; i++) {
		plain[i] = (unsigned char) (i & 0xFF);
	}
	in_buffer = (unsigned char*)malloc(INPUT_SIZE * 16 * sizeof(unsigned char));
	out_buffer = (unsigned char*)malloc(INPUT_SIZE * 16 * sizeof(unsigned char));
	for (long i = 0; i < INPUT_SIZE; i++) {
		memcpy(in_buffer + (i * 16 * sizeof(unsigned char)), plain, 16 * sizeof(unsigned char));
	}
}


int main(int argc, char *argv[])
{
	tbb::task_scheduler_init init(6);
	init2();

	AES aes(128);

	struct timespec start,end;
	double elapsed;

	clock_gettime(CLOCK_MONOTONIC, &start);

	tbb::parallel_for( long(0), INPUT_SIZE, [&]( long i ) {
		unsigned char *out = aes.EncryptECB(in_buffer + (i * 16 * sizeof(unsigned char)), plainLen, key, outLen);
		unsigned char *out2 = aes.DecryptECB(out, outLen, key);

		memcpy(out_buffer + (i * 16 * sizeof(unsigned char)), out2, 16 * sizeof(unsigned char));
    } );

	clock_gettime(CLOCK_MONOTONIC, &end);
  elapsed = (end.tv_sec - start.tv_sec);

	printf("TBB version: %d", TBB_INTERFACE_VERSION);
  printf("\nRunning Time: %f\n", elapsed);

	return 0;
}
