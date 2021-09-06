#include <string.h>
#include <inttypes.h>
#include <errno.h>  
#include <assert.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>

size_t readmemory(int pid, uint8_t *dest_buffer, const char *target_address, size_t size);


int disas_raw_code(unsigned char *custom_code, size_t code_size, unsigned long start_addr);
