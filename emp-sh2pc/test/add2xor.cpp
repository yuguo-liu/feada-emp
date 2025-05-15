#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstring>

using namespace emp;
using namespace std;

typedef unsigned int word32;
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string file = circuit_file_location+"/bristol_format/sha-256-multiblock.txt";

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "add_2_xor_p256.txt");

    Integer b {264, 0, BOB};
    Integer b_mask {264, 0, BOB};
    Integer p1 {264, 0, BOB};

    Integer a {264, 0, ALICE};
    Integer a_mask {264, 0, ALICE};
    Integer p2 {264, 0, ALICE};

    // block one = CircuitExecution::circ_exec->public_label(true);
    // block zero = CircuitExecution::circ_exec->public_label(false);

    Bit one(true);
    Bit zero(false);

    Integer result = a + b;

    // result.reveal<string>();

    // word32 p_array[8];
    // p_array[0] = 0xFFFFFFFFL;
    // p_array[1] = 0xFFFFFFFFL;
    // p_array[2] = 0xFFFFFFFFL;
    // p_array[3] = 0x00000000L;
    // p_array[4] = 0x00000000L;
    // p_array[5] = 0x00000000L;
    // p_array[6] = 0x00000001L;
    // p_array[7] = 0xFFFFFFFFL;

    // vector<Bit> p_bits;
    // for (int i = 0; i < 8; i++) {
    //     word32 tmp = p_array[i];
    //     for (int j = 0; j < 32; j++) {
    //         p_bits.push_back((tmp & 1) != 0 ? one : zero);
    //         tmp >>= 1;
    //     }
    // }

    // Integer p(p_bits);

    string a_s = p1.reveal<string>();
    // cout << a_s << endl;

    Bit to_mod = (result >= p1);

    // to_mod.reveal();

    vector<Bit> to_mod_v;
    for (int i = 0; i < 256 + 8; i++)
        to_mod_v.push_back(to_mod);
    Integer to_mod_i(to_mod_v);

    // to_mod_i.reveal<string>();

    result = (result - (p1 & to_mod_i)) ^ (a_mask ^ b_mask);

    // result.reveal<string>();

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}
