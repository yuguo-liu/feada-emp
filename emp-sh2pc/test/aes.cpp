#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

using namespace emp;
using namespace std;

typedef unsigned int word32;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string CF_AES = circuit_file_location + "/bristol_format/AES/aes128_full.txt";
BristolFormat AES(CF_AES.c_str());

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    setup_semi_honest(io, party);
    // setup_plain_prot(true, "aes_2pc.txt");

    Integer key_m_bob {256, "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f", BOB};

    Integer key_m_alice {256, 0, ALICE};

    Integer key_m = key_m_alice ^ key_m_bob;

    Integer c {128, 0};

    AES.compute(
        (block*) c.bits.data(),
        (block*) key_m.bits.data(),
        (block*) key_m.bits.data()
    );

    string str_c = c.reveal<string>();

    cout << str_c << endl;
    
    // finalize_plain_prot();
    finalize_semi_honest();

    delete io;

    return 0;
}

