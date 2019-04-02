#include "utils.hpp"

using namespace std;

string string_to_hex(const string& input) {
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();

    string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

// void hexdump(void *ptr, int buflen) {
//   unsigned char *buf = (unsigned char*)ptr;
//   int i, j;
//   for (i=0; i<buflen; i+=16) {
//     printf("%06x: ", i);
//     for (j=0; j<16; j++) 
//       if (i+j < buflen)
//         printf("%02x ", buf[i+j]);
//       else
//         printf("   ");
//     printf(" ");
//     for (j=0; j<16; j++) 
//       if (i+j < buflen)
//         printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
//     printf("\n");
//   }
// }
