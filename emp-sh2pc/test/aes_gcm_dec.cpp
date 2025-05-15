#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

#define BLOCK 50
#define AUTH_BLOCK 1

using namespace emp;
using namespace std;

typedef unsigned int word32;

void concat_integer(Integer &c, Integer &a, Integer &b);
void lift_to_high_bits(Integer &c, Integer &a);

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string CF_GFMult128 = circuit_file_location + "/bristol_format/AES/GFMult128_.txt";
string CF_AES = circuit_file_location + "/bristol_format/AES/aes128_full.txt";
BristolFormat GFMult128(CF_GFMult128.c_str());
BristolFormat AES(CF_AES.c_str());

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "aes-gcm-dec-" + std::to_string(BLOCK) + ".txt");

    Integer ciphertexts[BLOCK];                 // ciphertexts held by Bob
    for (int i = 0; i < BLOCK; i++) {
        ciphertexts[i] = Integer {128, 0, BOB};
    }
    Integer tag {128, 0, BOB};                  // 
    Integer len_c_data {128, 0, BOB};           // length of ciphertext
    Integer bob_key_share {128, 0, BOB};        // aes gcm share of key
    Integer bob_counter_0_share {128, 0, BOB};  // aes gcm share of iv (usage: iv || 0^31 || 1)
    Integer bob_padding_mask {128, 0, BOB};     // padding mask for non-multi-block plaintext

    Integer auth_data[AUTH_BLOCK];                              // auth data input by alice
    for (int i = 0; i < AUTH_BLOCK; i++) {
        auth_data[i] = Integer {128, 0, ALICE};
    }
    Integer len_a_data {128, 0, ALICE};                         // length of associated data (real length << 64)
    Integer alice_key_share {128, 0, ALICE};                    // aes gcm share of key
    Integer alice_counter_0_share {128, 0, ALICE};              // aes gcm share of iv (usage: iv || 0^32)
    
    Integer dummy [BLOCK - AUTH_BLOCK + 2];
    for (int i = 0; i < BLOCK - AUTH_BLOCK + 2; i++) {
        dummy[i] = Integer {128, 0, ALICE};
    }

    // key and counter 0
    Integer key       = bob_key_share ^ alice_key_share;
    Integer counter_0 = bob_counter_0_share ^ alice_counter_0_share;

    // generate h and ek counter 0
    Integer zero {128, 0};
    Integer one {128, 1};
    Integer h {128, 0};
    Integer aes_in {256, 0};

    // cout << zero.reveal<string>() << endl;
    lift_to_high_bits(aes_in, key);
    // cout << aes_in.reveal<string>() << endl;
    AES.compute(
        (block*) h.bits.data(),
        (block*) aes_in.bits.data(),
        (block*) zero.bits.data()
    );

    Integer ek_counter_0 {128, 0};
    aes_in = Integer {256, 0};
    concat_integer(aes_in, key, counter_0);
    // cout << aes_in.reveal<string>() << endl;
    AES.compute(
        (block*) ek_counter_0.bits.data(),
        (block*) aes_in.bits.data(),
        (block*) zero.bits.data()
    );

    // generate pads
    Integer pads[BLOCK];
    Integer counter = counter_0;
    for (int i = 0; i < BLOCK; i++) {
        counter = counter + one;
        aes_in = Integer {256, 0};
        concat_integer(aes_in, key, counter);

        pads[i] = Integer {128, 0};
        // cout << aes_in.reveal<string>() << endl;
        AES.compute(
            (block*) pads[i].bits.data(),
            (block*) aes_in.bits.data(),
            (block*) zero.bits.data()
        );
    }

    // h.reveal<string>();

    // encrypt
    Integer plaintexts[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
        plaintexts[i] = pads[i] ^ ciphertexts[i];
    }

    // padding mask
    plaintexts[BLOCK - 1] = plaintexts[BLOCK - 1] & bob_padding_mask;

    // hashing
    Integer ghash {128, 0};
    Integer multiply {128, 0};

    for (int i = 0; i < AUTH_BLOCK; i++) {
        ghash = ghash ^ auth_data[i];

        multiply = Integer {128, 0};
        GFMult128.compute(
            (block*) multiply.bits.data(),
            (block*) ghash.bits.data(),
            (block*) h.bits.data()
        );

        ghash = multiply;
    }

    for (int i = 0; i < BLOCK; i++) {
        ghash = ghash ^ ciphertexts[i];

        multiply = Integer {128, 0};
        GFMult128.compute(
            (block*) multiply.bits.data(),
            (block*) ghash.bits.data(),
            (block*) h.bits.data()
        );

        ghash = multiply;
    }

    // length info
    Integer length_info {128, 0};
    length_info = len_a_data ^ len_c_data;

    ghash = ghash ^ length_info;
    multiply = Integer {128, 0};
    GFMult128.compute(
        (block*) multiply.bits.data(),
        (block*) ghash.bits.data(),
        (block*) h.bits.data()
    );

    ghash = multiply;

    // xor ek_counter0

    ghash = ghash ^ ek_counter_0;

    Bit is_equal = (tag == ghash);
    vector<Bit> mask;
    for (int i = 0; i < 128; i++) {
        mask.insert(mask.end(), is_equal);
    }

    Integer mask_int(mask);

    for (int i = 0; i < BLOCK; i++) {
        plaintexts[i] = (plaintexts[i] & mask_int);
    }

    is_equal.reveal();

    for (int i = 0; i < BLOCK; i++) {
        string c = plaintexts[i].reveal<string>();
        cout << "plaintext block " << i << ": " << c << endl;
    }
    
    finalize_plain_prot();
    // finalize_semi_honest();

    delete io;

    return 0;
}

void concat_integer(Integer &c, Integer &a, Integer &b) {
    assert(c.size() == a.size() + b.size());

    for (size_t i = 0; i < a.size(); i++) {
        c.bits[i] = a.bits[i];
    }

    for (size_t i = 0; i < b.size(); i++) {
        c.bits[i + a.size()] = b.bits[i];
    }
}

void lift_to_high_bits(Integer &c, Integer &a) {
    assert(c.size() > a.size());

    for (size_t i = 0; i < a.size(); i++) {
        c.bits[i] = a.bits[i];
    }

    for (size_t i = 0; i < c.size() - a.size(); i++) {
        c.bits[i + a.size()] = Bit(false);
    }
}
