#include "verify.h"

using namespace std;

string proofFile("proof.pem");

int main() {
    cout << "Reading in PEM file\n";

    ifstream t(proofFile);
    string pemStr((istreambuf_iterator<char>(t)),
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
    return 0;
}