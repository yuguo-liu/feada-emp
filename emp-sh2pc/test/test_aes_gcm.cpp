#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstring>

using namespace emp;
using namespace std;

typedef unsigned int word32;
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string file = circuit_file_location+"/bristol_format/AES/aes128-full.txt";
BristolFormat AES(file.c_str());

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    setup_semi_honest(io, party);

    Integer key_msg {256, 0x000102030405060708090a0b0c0d0e0f};
    Integer key {128, 0x0f0e0d0c0b0a09080706050403020100};
    
    Integer cipher {128, 0};
    AES.compute(
        (block*) cipher.bits.data(),
        (block*) 
    )

    finalize_semi_honest();
    delete io;

    return 0;
}
