#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

#define BLOCK 128
#define AUTH_BLOCK 1

using namespace emp;
using namespace std;

typedef unsigned int word32;

void concat_integer(Integer &c, Integer &a, Integer &b);
void lift_to_high_bits(Integer &c, Integer &a);
int get_padded_len(int L);
void padding(block *input, block *output, int input_len);
void sha256(block *input, block *output, int input_len);
void change_endian(block *input, block *output, int input_len);

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string CF_GFMult128 = circuit_file_location + "/bristol_format/AES/GFMult128_.txt";
string CF_SHA256 = circuit_file_location + "/bristol_format/sha-256-multiblock.txt";
string CF_AES = circuit_file_location + "/bristol_format/AES/aes128_full.txt";
BristolFormat GFMult128(CF_GFMult128.c_str());
BristolFormat AES(CF_AES.c_str());

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "predicate-standard-aes-gcm-" + std::to_string(BLOCK) + ".txt");

    Integer plaintexts[BLOCK];                  // plaintexts held by Bob
    for (int i = 0; i < BLOCK; i++) {
        plaintexts[i] = Integer {128, 0, BOB};
    }
    Integer len_c_data {128, 0, BOB};           // length of ciphertext
    Integer bob_key_share {128, 0, BOB};        // aes gcm share of key
    Integer bob_counter_0_share {128, 0, BOB};  // aes gcm share of iv (usage: iv || 0^31 || 1)
    Integer bob_padding_mask {128, 0, BOB};     // padding mask for non-multi-block plaintext
    Integer dummy [AUTH_BLOCK + 2];
    for (int i = 0; i < AUTH_BLOCK + 2; i++) {
        dummy[i] = Integer {128, 0, BOB};
    }

    Integer plaintexts_wo_sensitive[BLOCK];                     // plaintexts without sensitive hold by alice
    for (int i = 0; i < BLOCK; i++) {
        plaintexts_wo_sensitive[i] = Integer {128, 0, ALICE};
    }
    Integer auth_data[AUTH_BLOCK];                              // auth data input by alice
    for (int i = 0; i < AUTH_BLOCK; i++) {
        auth_data[i] = Integer {128, 0, ALICE};
    }
    Integer len_a_data {128, 0, ALICE};                         // length of associated data (real length << 64)
    Integer alice_key_share {128, 0, ALICE};                    // aes gcm share of key
    Integer alice_counter_0_share {128, 0, ALICE};              // aes gcm share of iv (usage: iv || 0^32)
    Integer commitement {256, 0, ALICE};                        // commitment of sensitive data
    Integer r_com {128, 0, ALICE};                              // random number of commitment

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
    Integer ciphertexts[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
        ciphertexts[i] = pads[i] ^ plaintexts[i];
    }

    // padding mask
    ciphertexts[BLOCK - 1] = ciphertexts[BLOCK - 1] & bob_padding_mask;

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

    // check the commitment =?= SHA256((plaintexts xor plaintexts_wo_sensitive) || r_com)
    block plaintext[128 * BLOCK + 128];
    for (int i = 0; i < BLOCK; i++) {
        Integer tmp = plaintexts[i] ^ plaintexts_wo_sensitive[i];
        block* one_plaintext = (block*) tmp.bits.data();
        for (int j = 0; j < 128; j++) {
            plaintext[i * 128 + j] = one_plaintext[j];
        }
    }

    block* r_com_block = (block*) r_com.bits.data();
    for (int i = 0; i < 128; i++) {
        plaintext[128 * BLOCK + i] = r_com_block[i];
    }

    Bit commitment_plaintext_compute[256];
    sha256(plaintext, (block*) commitment_plaintext_compute, 128 * BLOCK + 128);

    for (int i = 0; i < 256 / 8; i++) {
        for (int j = 0; j < 4; j++) {
            Bit tmp = commitment_plaintext_compute[8 * i + j];
            commitment_plaintext_compute[8 * i + j] = commitment_plaintext_compute[8 * i + (7 - j)];
            commitment_plaintext_compute[8 * i + (7 - j)] = tmp;
        }
    }

    vector<Bit> hash_plaintext_compute_bits(commitment_plaintext_compute, commitment_plaintext_compute + 256);
    Integer hash_to_check(hash_plaintext_compute_bits);

    // add mask to ciphertext and tag (if mask is all 0, bob can get nothing)
    Bit is_equal = (hash_to_check == commitement);
    
    vector<Bit> mask;
    for (int i = 0; i < 128; i++) {
        mask.insert(mask.end(), is_equal);
    }

    Integer mask_int(mask);

    for (int i = 0; i < BLOCK; i++) {
        ciphertexts[i] = (ciphertexts[i] & mask_int);
    }

    ghash = (ghash & mask_int);

    is_equal.reveal();

    for (int i = 0; i < BLOCK; i++) {
        string c = ciphertexts[i].reveal<string>();
        cout << "cipher block " << i << ": " << c << endl;
    }

    string g = ghash.reveal<string>();
    cout << "ghash: " << g << endl;
    
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

void sha256(block *input, block *output, int input_len) {
    // new input
    auto input_new = new block[input_len];

    // reverse the bits
    change_endian(input, input_new, input_len);

    // first, do the padding
    int padded_len = get_padded_len(input_len);

    // allocate the padding
    block *padded_input = new block[padded_len];

    // pad
    padding(input_new, padded_input, input_len);

    delete[] input_new;

    // number of blocks
    int num_blocks = padded_len / 512;

    // start the hashing
    // first block
    word32 digest[8];
    digest[0] = 0x6A09E667L;
    digest[1] = 0xBB67AE85L;
    digest[2] = 0x3C6EF372L;
    digest[3] = 0xA54FF53AL;
    digest[4] = 0x510E527FL;
    digest[5] = 0x9B05688CL;
    digest[6] = 0x1F83D9ABL;
    digest[7] = 0x5BE0CD19L;

    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    auto input_to_sha256_circuit = new block[768];
    block output_from_sha256_circuit[256];

    block digest_bits[256];
    for (int i = 0; i < 8; i++) {
        word32 tmp = digest[i];
        for (int j = 0; j < 32; j++) {
            digest_bits[i * 32 + j] = (tmp & 1) != 0 ? one : zero;
            tmp >>= 1;
        }
    }

    Integer zero_int {0, 0, PUBLIC};

    for (int b = 0; b < num_blocks; b++) {
        // the first 512 bits -> the padded data
        // the rest of the 256 bits -> the 8 * 32 bits of the digest values

        for (int i = 0; i < 512; i++) {
            input_to_sha256_circuit[i] = padded_input[b * 512 + i];
        }

        for (int i = 0; i < 256; i++) {
            input_to_sha256_circuit[512 + i] = digest_bits[i];
        }

        BristolFormat bf(CF_SHA256.c_str());
        bf.compute(output_from_sha256_circuit, input_to_sha256_circuit, (block*) zero_int.bits.data());

        for (int i = 0; i < 256; i++) {
            digest_bits[i] = output_from_sha256_circuit[i];
        }
    }

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 8; k++) {
                output[i * 32 + j * 8 + k] = output_from_sha256_circuit[i * 32 + 8 * (3 - j) + k];
            }
        }
    }

    delete[] padded_input;
    delete[] input_to_sha256_circuit;
}

int get_padded_len(int L) {
    // find K such that L + 1 + K + 64 is a multiple of 512
    int K = 512 - ((L + 1 + 64) % 512);
    K %= 512;    // If L + 1 + 64 is already a multiple of 512, K = 0

    return L + 1 + K + 64;
}

void padding(block *input, block *output, int input_len) {
    block one = CircuitExecution::circ_exec->public_label(true);
    block zero = CircuitExecution::circ_exec->public_label(false);

    for (int i = 0; i < input_len; i++) {
        output[i] = input[i];
    }

    int offset = input_len;

    // add one bit "1"
    output[offset++] = one;

    // find K such that L + 1 + K + 64 is a multiple of 512
    int K = 512 - ((input_len + 1 + 64) % 512);
    K %= 512;    // If L + 1 + 64 is already a multiple of 512, K = 0

    // add K bits "0"
    for (int i = 0; i < K; i++) {
        output[offset++] = zero;
    }

    if (input_len > 65536) {
        error("The circuit synthesizer assumes that input_len is small (< 8192 bits).");
    }

    // add the length of L
    // for simplicity, assume that the higher 48 bits are zero---since our input is going to be small anyway
    // the remaining 16 bits give you 2^15-1 bits to spend, about 8KB
    for (int i = 0; i < 48; i++) {
        output[offset++] = zero;
    }

    for (int i = 0; i < 16; i++) {
        int bool_test = (input_len & (1 << (16 - 1 - i))) != 0;
        output[offset++] = bool_test ? one : zero;
    }
}

void change_endian(block *input, block *output, int input_len) {
    if (input_len % 8 != 0) {
        error("The circuit synthesizer can only convert the endianness for bytes.");
    }

    int num_bytes = input_len / 8;
    for (int i = 0; i < num_bytes; i++) {
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = input[i * 8 + j];
        }
    }
}