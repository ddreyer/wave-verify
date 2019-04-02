#ifndef __UTILS_H_INCLUDED__
#define __UTILS_H_INCLUDED__

// #define EDEBUG 0

#include <string>
#include "Enclave_t.h"

using namespace std;

#ifdef DEBUG
  #define verify_print(...) ocall_print(__VA_ARGS__)
#else
  #define verify_print(...)
#endif

/* useful functions for debugging */
string string_to_hex(const string& input);

// void hexdump(void *ptr, int buflen);

#endif
