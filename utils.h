#ifndef __UTILS_H_INCLUDED__
#define __UTILS_H_INCLUDED__

#include <iostream>
#include <string>
#include <string.h>
#include "Enclave_t.h"

using namespace std;

static const string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

string base64_decode(string const& encoded_string);

sgx_status_t verify_error(string message);

/* useful functions for debugging */
string string_to_hex(const string& input);

// void hexdump(void *ptr, int buflen);

#endif
