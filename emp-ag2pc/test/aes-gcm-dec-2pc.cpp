#include <emp-tool/emp-tool.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "test/single_execution.h"
#include "test/plaintext_sha256.h"
#include <time.h>

#define NAME(variable) (#variable)

using namespace std;
using namespace emp;

string io_bob_ciphertext      = "";
string io_bob_tag             = "00000000000000000000000000000000";
string io_bob_len_c           = "00000000000000000000000000000000";
string io_bob_key_share       = "00000000000000000000000000000000";
string io_bob_counter_0_share = "00000000000000000000000000000000";
string io_bob_padding_mask    = "00000000000000000000000000000000";

string io_alice_auth_data       = "";
string io_alice_len_a           = "00000000000000000000000000000000";
string io_alice_key_share       = "00000000000000000000000000000000";
string io_alice_counter_0_share = "00000000000000000000000000000000";
string io_alice_dummy           = "";

string reverse_hex_binary(const string &hex);
string int_to_hex_16(int value);
string pad_hex_string(const string& hex_str);
void debug_io(string a);
string padding_mask(int length_plaintext);

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	// NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);

    if (argc != 13) {
        cerr << "Parameter error: expect 13 get " << argc << endl;
        exit(1);
    }

    string host = argv[12];
	NetIO* io = new NetIO(party==ALICE ? nullptr:host.c_str(), port);
    
    string bob_c                    = argv[3];
    string bob_tag                  = argv[4];
    string bob_key_share            = argv[5];
    string bob_iv_share             = argv[6];

    string alice_auth_data          = argv[7];
    string alice_key_share          = argv[8];
    string alice_iv_share           = argv[9];

    int len_c_i = atoi(argv[10]);
    int len_a_i = atoi(argv[11]);

    int plain_block = (int) len_c_i / 128;
    int auth_block  = (int) len_a_i / 128;
    plain_block += (len_c_i % 128 == 0) ? 0 : 1;
    auth_block  += (len_a_i % 128 == 0) ? 0 : 1;

    string len_c = int_to_hex_16(bob_c.length() * 4);
    string len_a = int_to_hex_16(alice_auth_data.length() * 4);

    if (party == BOB) {
        io_bob_ciphertext        = pad_hex_string(bob_c);
        io_bob_tag               = bob_tag;
        io_bob_len_c             = "0000000000000000" + len_c;
        io_bob_key_share         = reverse_hex_binary(bob_key_share);
        io_bob_counter_0_share   = reverse_hex_binary(bob_iv_share + "00000001");
        io_bob_padding_mask      = padding_mask(len_c_i);
        
        io_alice_auth_data       = string(auth_block * 32, '0');
        io_alice_len_a           = len_a + "0000000000000000";
        io_alice_dummy           = string((plain_block - auth_block + 2) * 32, '0');
        
        debug_io(io_bob_ciphertext);
        debug_io(io_bob_tag);
        debug_io(io_bob_len_c);
        debug_io(io_bob_key_share);
        debug_io(io_bob_counter_0_share);
        debug_io(io_bob_padding_mask);

        debug_io(io_alice_auth_data);
        debug_io(io_alice_len_a);
        debug_io(io_alice_key_share);
        debug_io(io_alice_counter_0_share);
        debug_io(io_alice_dummy);

        string in = io_bob_ciphertext + io_bob_tag + io_bob_len_c + io_bob_key_share + io_bob_counter_0_share + io_bob_padding_mask
                    + io_alice_auth_data + io_alice_len_a + io_alice_key_share + io_alice_counter_0_share + io_alice_dummy;
        cout << in.length() * 4 << endl;
        string c = ag2pc_exec(party, io, circuit_file_location+"AES/aes-gcm-dec-" + std::to_string(plain_block) + ".txt", in);

        cout << c.substr(0, 1) << endl;
        cout << c.substr(1, (int) (len_c_i / 4)) << endl;
    } else {
        io_bob_ciphertext        = string(plain_block * 32, '0');
        io_bob_len_c             = "0000000000000000" + len_c;
        
        io_alice_auth_data       = pad_hex_string(alice_auth_data);
        io_alice_len_a           = len_a + "0000000000000000";
        io_alice_key_share       = reverse_hex_binary(alice_key_share);
        io_alice_counter_0_share = reverse_hex_binary(alice_iv_share + "00000000");
        io_alice_dummy           = string((plain_block - auth_block + 2) * 32, '0');

        // debug_io(io_bob_plaintext);
        // debug_io(io_bob_len_c);
        // debug_io(io_bob_key_share);
        // debug_io(io_bob_counter_0_share);

        // debug_io(io_alice_auth_data);
        // debug_io(io_alice_len_a);
        // debug_io(io_alice_key_share);
        // debug_io(io_alice_counter_0_share);
        // debug_io(io_alice_dummy);

        string in = io_bob_ciphertext + io_bob_tag + io_bob_len_c + io_bob_key_share + io_bob_counter_0_share + io_bob_padding_mask 
                    + io_alice_auth_data + io_alice_len_a + io_alice_key_share + io_alice_counter_0_share + io_alice_dummy;
        cout << in.length() * 4 << endl;
        string c = ag2pc_exec(party, io, circuit_file_location+"AES/aes-gcm-dec-" + std::to_string(plain_block) + ".txt", in);

        cout << c.substr(0, 1) << endl;
        cout << c.substr(1, (int) (len_c_i / 4)) << endl;
    }

	delete io;
	return 0;
}

// Function to convert hex string to binary string
string hex_to_bin(const string &hex)
{
    string bin;
    for (char c : hex)
    {
        int value = stoi(string(1, c), nullptr, 16);
        bin += bitset<4>(value).to_string(); // Convert each hex digit to 4-bit binary
    }
    return bin;
}

// Function to convert binary string to hex string
string bin_to_hex(const string &bin)
{
    stringstream hex;
    for (size_t i = 0; i < bin.size(); i += 4)
    {
        int value = stoi(bin.substr(i, 4), nullptr, 2);
        hex << std::hex << value; // Convert 4-bit binary to hex digit
    }
    return hex.str();
}

// Function to reverse the binary representation of a hex string
string reverse_hex_binary(const string &hex)
{
    string binary = hex_to_bin(hex); // Convert hex to binary
    reverse(binary.begin(), binary.end()); // Reverse binary string
    return bin_to_hex(binary); // Convert reversed binary back to hex
}

// Function to convert an integer to a 16-character hexadecimal string
string int_to_hex_16(int value)
{
    stringstream stream;
    stream << std::setfill('0') << std::setw(16) << std::hex << std::uppercase << (unsigned int)value;
    return stream.str();
}

/**
 * Pads a hexadecimal string with zeros so that its length is a multiple of 32.
 * If the string length is already a multiple of 32, no padding is applied.
 * 
 * @param hex_str The input hexadecimal string to be padded.
 * @return The padded hexadecimal string.
 */
string pad_hex_string(const string& hex_str) {
    // Calculate the length of the input string
    size_t length = hex_str.length();
    
    // Calculate the remainder when the length is divided by 32
    size_t remainder = length % 32;
    
    // If the remainder is not zero, calculate the number of zeros needed for padding
    if (remainder != 0) {
        size_t padding_length = 32 - remainder;
        
        // Create a string with the required number of zeros
        string padding(padding_length, '0');
        
        // Append the padding to the original string
        return hex_str + padding;
    }
    
    // If the length is already a multiple of 32, return the original string
    return hex_str;
}

void debug_io(string a) {
    cout << NAME(a) << " [" << a.length() << "]: " << a << endl;
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