#include "verify.h"

using namespace std;

/* hardcoded proof file to read from */
string proofFile("proof.pem");

int main() {
    cout << "Reading in PEM file\n";

    ifstream file;
    try {
        file.open(proofFile);
    } catch (const ifstream::failure& e) {
        cerr << "exception opening/reading proof file " << proofFile << "\n";
        return -1;
    }
    string pemStr((istreambuf_iterator<char>(file)),
                             istreambuf_iterator<char>());

    // extract proof content from .pem file
    pemStr.erase(0, pemStr.find("\n") + 1);
    int idx = pemStr.find("-----END WAVE");
    if (idx == string::npos) {
        cerr << "invalid proof .pem file\n";
        return -1;
    }
    pemStr.erase(idx, pemStr.find("\n", idx));
    pemStr.erase(remove(pemStr.begin(), pemStr.end(), '\n'), pemStr.end());
    int ret = verify(pemStr);
    if (ret) {
        cerr << "verifying " << proofFile << " failed\n";
        return -1;
    }
    cout << "verifing " << proofFile << " succeeded\n";
    return 0;
}
