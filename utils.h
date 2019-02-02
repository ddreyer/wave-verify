#ifndef __UTILS_H_INCLUDED__
#define __UTILS_H_INCLUDED__

#include <string>
#include "Enclave_t.h"

using namespace std;

// #define EDEBUG 0

#ifdef EDEBUG
  #define enclave_print(...) ocall_print(__VA_ARGS__)
#else
  #define enclave_print(...)
#endif

/* useful functions for debugging */
string string_to_hex(const string& input);

// void hexdump(void *ptr, int buflen);

#endif
