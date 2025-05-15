#include "emp-tool/emp-tool.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <cstdint>

#define BLOCK 50

using namespace emp;
using namespace std;

typedef unsigned int word32;

int get_padded_len(int L);
void padding(block *input, block *output, int input_len);
void sha256(block *input, block *output, int input_len);
void change_endian(block *input, block *output, int input_len);

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
string CF_GFMult128 = circuit_file_location+"/bristol_format/AES/GFMult128_.txt";
string CF_SHA256 = circuit_file_location+"/bristol_format/sha-256-multiblock.txt";
BristolFormat GFMult128(CF_GFMult128.c_str());

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

    // setup_semi_honest(io, party);
    setup_plain_prot(true, "general_enc_ghash_" + std::to_string(BLOCK) + ".txt");

    Integer plaintexts[BLOCK];                  // plaintexts held by Bob
    for (int i = 0; i < BLOCK; i++) {
        plaintexts[i] = Integer {128, 0, BOB};
    }

    Integer len_c_data {128, 0, BOB};           // length of ciphertext

    Integer bob_mask {128, 0, BOB};             // mask of bob

    // Integer bob_dummy {512, 0, BOB};            // align the input of alice
    Integer bob_padding_mask {128, 0, BOB};     // padding mask for non-multi-block plaintext
    Integer bob_dummy {128, 0, BOB};            // align the input of alice

    Integer ghash {128, 0, ALICE};              // ghash of associated data (computed locally by Alice)

    Integer pads[BLOCK];                        // pads of AES (computed locally by Alice)
    for (int i = 0; i < BLOCK; i++) {
        pads[i] = Integer {128, 0, ALICE};
    }

    Integer h {128, 0, ALICE};                  // power sequence of h = AES(k, 0) (computed locally by Alice)

    Integer ek_counter0 {128, 0, ALICE};        // value of AES(k, CTR) (computed locally by Alice)

    Integer len_a_data {128, 0, ALICE};         // length of associated data (real length << 64)

    // Integer hash_plaintext {256, 0, ALICE};     // hash of plaintext

    // encrypt
    Integer ciphertexts[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
        ciphertexts[i] = pads[i] ^ plaintexts[i];
    }

    // padding mask
    ciphertexts[BLOCK - 1] = ciphertexts[BLOCK - 1] & bob_padding_mask;

    // hashing
    Integer multiply {128, 0};
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
    length_info = len_a_data + len_c_data;

    ghash = ghash ^ length_info;
    multiply = Integer {128, 0};
    GFMult128.compute(
        (block*) multiply.bits.data(),
        (block*) ghash.bits.data(),
        (block*) h.bits.data()
    );

    ghash = multiply;

    // xor ek_counter0

    ghash = ghash ^ ek_counter0;

    for (int i = 0; i < BLOCK; i++) {
        ciphertexts[i] = ciphertexts[i] ^ bob_mask;
    }

    ghash = ghash ^ bob_mask;

    // is_equal.reveal();
    // hash_to_check.reveal<string>();
    // hash_plaintext.reveal<string>();

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

    if (input_len > 8191) {
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