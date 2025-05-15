#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
#include "test/aes128/aes128gcm.h"
using namespace std;
using namespace emp;

#define LENGTH_BLOCK 128
#define ADD_DATA_BLOCK 1

void hex_str_2_unsigned_char(string s, unsigned char* uc);
void print_unsigned_char(unsigned char* uc, int len);
string unsigned_char_2_hex_str(unsigned char* uc, int len);
string utf8_to_hex(const std::string &utf8_str);
string int_to_hex(const int num);
string generate_random_hex_string(size_t length);
string xorHexStrings(const std::string& hexStr1, const std::string& hexStr2);
string padding_mask(int length_plaintext);

string io_alice_ghash = "00000000000000000000000000000000";
string io_alice_plaintext_wo_sensitive = "";
string io_alice_pads = "";
string io_alice_h = "00000000000000000000000000000000";
string io_alice_ek_counter0 = "00000000000000000000000000000000";
string io_alice_len_a_data = "00000000000000000000000000000000";
string io_alice_commitment = "0000000000000000000000000000000000000000000000000000000000000000";
string io_alice_r_com = "00000000000000000000000000000000";

string io_bob_plaintext = "";
string io_bob_len_c_data = "00000000000000000000000000000000";
string io_bob_mask = "00000000000000000000000000000000";
string io_bob_padding_mask = "00000000000000000000000000000000";
string io_bob_dummy = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
string io_bob_dummies = "";

string res = "";
/**
 * Alice: BTC holder
 *      ghash: the ghash value of add data
 *      pads: the random pad of AES
 *      h: the hash key (AES(k, 0))
 *      ek_counter0: the value of AES(k, CTR)
 *      len_a_data: the length of add data
 *      hash_plaintext: the plaintext
 * 
 * Bob: USD holder
 *      plaintexts: the plaintext of msg
 *      len_c_data: the length of ciphertext/plaintext
 *      bob_mask: the random mask of Bob
 */


int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
//	io->set_nodelay();

    if (argc != 11) {
        cerr << "Parameter error: expect 11 get " << argc << endl;
        exit(1);
    }

    int length_plaintext = atoi(argv[6]);
    // int length_plaintext = 16;
    int BLOCK = (int) (length_plaintext / LENGTH_BLOCK);
    BLOCK += (length_plaintext % LENGTH_BLOCK != 0);
    // string seqnum = "0000000000000001";
    string seqnum = argv[7];

    for (int i = 0; i < BLOCK; i++) {
        io_alice_pads += "00000000000000000000000000000000";
        io_alice_plaintext_wo_sensitive += "00000000000000000000000000000000";
        io_bob_plaintext += "00000000000000000000000000000000";
        io_bob_dummies += "00000000000000000000000000000000";
    }

    if (party == ALICE) {
        // const string derived_key = "e65ea5b51636d00404ff95f4381335abd1f5d5e9";
        // const string add_data_o = "00000000000000011503030002";
        const string derived_key = argv[3];
        const string add_data_o = argv[4];
        const string commitment = argv[8];
        const string r_com = argv[9];
        const string msg_wo_sensitive = argv[10];

        string key_c_str = derived_key.substr(0, 32);
        string iv_c_str = derived_key.substr(32, 8);
        string add_data_str = add_data_o;
        int len_iv = iv_c_str.length();
        int len_add_data = add_data_o.length();
        int diff = 0;

        iv_c_str = iv_c_str + seqnum;

        for (int i = 0; i < 32 - len_add_data; i++) {
            add_data_str = add_data_str + "0";
            diff += 4;
        }

        unsigned char key_c[16];
        unsigned char iv_c[12];
        unsigned char add_data[ADD_DATA_BLOCK * 16];

        hex_str_2_unsigned_char(key_c_str, key_c);
        hex_str_2_unsigned_char(iv_c_str, iv_c);
        hex_str_2_unsigned_char(add_data_str, add_data);

        unsigned char h_c[16] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        unsigned char counter_c[16] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        unsigned char ek_counter0[16] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        unsigned char pads[BLOCK][16];

        InitialHashSubkey(h_c, key_c);
        J0Definition(counter_c, iv_c);
        aes128e(ek_counter0, counter_c, key_c);
        IncrementingFunction(counter_c);

        for (int i = 0; i < BLOCK; i++) {
            // print_unsigned_char(counter_c, 16);
            aes128e(pads[i], counter_c, key_c);
            IncrementingFunction(counter_c);
        }
    
        // for (int i = 0; i < BLOCK; i++) {
        //     print_unsigned_char(pads[i], 16);
        // }

        unsigned char ghash_add_data[16];

        GHASH(ghash_add_data, h_c, add_data, 16 * ADD_DATA_BLOCK);

        io_alice_ghash = unsigned_char_2_hex_str(ghash_add_data, 16);

        // cout << "ALICE ghash: " << io_alice_ghash << endl;
        
        io_alice_pads = "";
        for (int i = 0; i < BLOCK; i++) {
            io_alice_pads += unsigned_char_2_hex_str(pads[i], 16);
        }

        io_alice_h = unsigned_char_2_hex_str(h_c, 16);
        io_alice_ek_counter0 = unsigned_char_2_hex_str(ek_counter0, 16);
        io_alice_len_a_data = int_to_hex(ADD_DATA_BLOCK * 128 - diff) + "0000000000000000";
        io_alice_commitment = commitment;
        io_alice_r_com = r_com;
        io_alice_plaintext_wo_sensitive = msg_wo_sensitive;
        // cout << io_alice_pads << endl;

        if (length_plaintext % LENGTH_BLOCK != 0)
            for (int i = 0; i < (LENGTH_BLOCK - length_plaintext % LENGTH_BLOCK) / 4; i++)
                io_alice_plaintext_wo_sensitive = io_alice_plaintext_wo_sensitive + "0";

        string in = io_bob_plaintext + io_bob_len_c_data + io_bob_mask + io_bob_padding_mask + io_bob_dummy + io_bob_dummies 
                    + io_alice_ghash  + io_alice_plaintext_wo_sensitive + io_alice_pads + io_alice_h + io_alice_ek_counter0 + io_alice_len_a_data + io_alice_commitment + io_alice_r_com;
        cout << party << ": " << in.length() << endl;
        cout << party << ": " << in << endl;

        res = ag2pc_exec(party, io, circuit_file_location + "/AES/predicate_enc_ghash_" + to_string(BLOCK) + ".txt", in);

        string correctness = res.substr(0, 1);
        // string ciphertext = res.substr(0, (int) length_plaintext / 4);
        // string tag = res.substr(BLOCK * 32);

        if (correctness == "0") {
            cerr << "ALICE: Bob's msg cannot pass the predicate" << endl;
            cout << "error" << endl;
        } else {
            cout << "ALICE: Encrypt correctly" << endl;
            cout << "ok" << endl;
        }
    } else {
        // const string msg_o = "0214";
        const string msg_o = argv[5];
        
        // io_bob_plaintext = utf8_to_hex(msg_o);
        io_bob_plaintext = msg_o;
        io_bob_len_c_data = "0000000000000000" + int_to_hex(length_plaintext);
        io_bob_mask = generate_random_hex_string(32);

        if (length_plaintext % LENGTH_BLOCK != 0)
            for (int i = 0; i < (LENGTH_BLOCK - length_plaintext % LENGTH_BLOCK) / 4; i++)
                io_bob_plaintext = io_bob_plaintext + "0";
        
        cout << party << ": " << io_bob_plaintext << endl;

        io_bob_padding_mask = padding_mask(length_plaintext);

        string in = io_bob_plaintext + io_bob_len_c_data + io_bob_mask + io_bob_padding_mask + io_bob_dummy + io_bob_dummies 
                    + io_alice_ghash  + io_alice_plaintext_wo_sensitive + io_alice_pads + io_alice_h + io_alice_ek_counter0 + io_alice_len_a_data + io_alice_commitment + io_alice_r_com;
        cout << party << ": " << in.length() << endl;
        cout << party << ": " << in << endl;

        res = ag2pc_exec(party, io, circuit_file_location + "/AES/predicate_enc_ghash_" + to_string(BLOCK) + ".txt", in);

        cout << res << endl;
        cout << io_bob_mask << endl;
        string correctness = res.substr(0, 1);
        string ciphertext = res.substr(1, BLOCK * 32);
        string tag = res.substr(BLOCK * 32 + 1);

        if (correctness == "0") {
            cout << "BOB: msg cannot pass the predicate" << endl;
            cout << "error" << endl;
        } else {
            string mask_ciphertext = "";
            for (int i = 0; i < BLOCK; i++) {
                mask_ciphertext += io_bob_mask;
            }

            ciphertext = xorHexStrings(ciphertext, mask_ciphertext);
            tag = xorHexStrings(tag, io_bob_mask);

            cout << ciphertext.substr(0, (int) length_plaintext / 4) << endl;
            cout << tag << endl;
        }
    }

	delete io;
	return 0;
}

void hex_str_2_unsigned_char(string s, unsigned char* uc) {
    const int len = s.length() / 2;
    for (int i = 0; i < len; i++) {
        uc[i] = stoi(s.substr(i * 2, 2).c_str(), 0, 16);
    }
}

void print_unsigned_char(unsigned char* uc, int len) {
    cout << "[";
    for (int i = 0; i < len; i++) {
        cout << setfill('0') << setw(2) << hex << (unsigned) uc[i];
        if (i < len - 1) cout << ", ";
    }
    cout << "]" << endl;
}

string unsigned_char_2_hex_str(unsigned char* uc, int len) {
    string s = "";
    for (int i = 0; i < len; i++) {
        ostringstream ss;
        ss << setfill('0') << setw(2) << hex << (int) uc[i];
        s += ss.str();
    }
    return s;
}

string utf8_to_hex(const string &utf8_str) {
    stringstream hex_stream;

    for (unsigned char c : utf8_str) {
        hex_stream << setw(2) << setfill('0') << hex << (int)c;
    }

    return hex_stream.str();
}

string int_to_hex(const int num) {
    stringstream hex_stream;

    hex_stream << setw(16) << setfill('0') << hex << num;

    return hex_stream.str();
}

string generate_random_hex_string(size_t length) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 15);

    stringstream ss;

    for (size_t i = 0; i < length; ++i) {
        int random_digit = dis(gen);
        ss << hex << random_digit;
    }

    return ss.str();
}

void hexStringToBytes(const string& hexStr, unsigned char* bytes) {
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string byteStr = hexStr.substr(i, 2); 
        bytes[i / 2] = static_cast<unsigned char>(stoi(byteStr, nullptr, 16));
    }
}

string bytesToHexString(const unsigned char* bytes, size_t length) {
    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << setw(2) << setfill('0') << hex << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

string xorHexStrings(const string& hexStr1, const string& hexStr2) {
    if (hexStr1.length() != hexStr2.length()) {
        exit(-1);
    }

    size_t length = hexStr1.length() / 2;
    unsigned char* bytes1 = new unsigned char[length];
    unsigned char* bytes2 = new unsigned char[length];
    unsigned char* resultBytes = new unsigned char[length];

    hexStringToBytes(hexStr1, bytes1);
    hexStringToBytes(hexStr2, bytes2);

    for (size_t i = 0; i < length; ++i) {
        resultBytes[i] = bytes1[i] ^ bytes2[i];
    }

    string result = bytesToHexString(resultBytes, length);

    delete[] bytes1;
    delete[] bytes2;
    delete[] resultBytes;

    return result;
}

string padding_mask(int length_plaintext) {
    /**
     * generating padding mask for aes-gcm in the case that 128 is not a factor of length plaintext
     * generates a 128-bit hex that the first m bits are 1, and the last 128 - m bits are 0
     */
    int m = length_plaintext % 128;

    uint64_t high = 0;
    uint64_t low = 0;

    if (m > 0) {
        if (m < 64) {
            high = ((1ULL << m) - 1) << (64 - m);
        } else {
            high = ~0ULL;
            low = ((1ULL << (m - 64)) - 1) << (128 - m);
        }
    } else {
        high = ~0ULL;
        low = ~0ULL;
    }

    uint64_t result_high = high;
    uint64_t result_low = low;

    stringstream ss;
    ss << hex << setw(16) << setfill('0') << result_high;
    ss << setw(16) << setfill('0') << result_low;

    return ss.str();
}