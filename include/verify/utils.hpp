#ifndef __UTILS_H_INCLUDED__
#define __UTILS_H_INCLUDED__

#include <string>
#include <iostream>

using namespace std;

#define DEBUG 0

#ifdef DEBUG
  #define verify_print(...) printf(__VA_ARGS__)
#else
  #define verify_print(...)
#endif

/* useful functions for debugging */
string string_to_hex(const string& input);

// void hexdump(void *ptr, int buflen);

#endif
