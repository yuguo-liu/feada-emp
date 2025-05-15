#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

using namespace emp;
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "input_test_3.txt");

    Integer b_1 {32, 0, BOB};
    Integer b_2 {16, 0, BOB};
    Integer b_3 {32, 0, BOB};

    Integer a_1 {32, 0, ALICE};
    Integer a_2 {16, 0, ALICE};
    Integer a_3 {32, 0, ALICE};
    Integer a_4 {32, 0, ALICE};
    Integer a_5 {32, 0, ALICE};

    a_1.reveal<string>();
    a_2.reveal<string>();
    a_3.reveal<string>();
    a_4.reveal<string>();
    a_5.reveal<string>();
    b_1.reveal<string>();
    b_2.reveal<string>();
    b_3.reveal<string>();

    finalize_plain_prot();
    // finalize_semi_honest();
    delete io;

    return 0;
}