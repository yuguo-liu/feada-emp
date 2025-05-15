#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
using namespace std;
using namespace emp;

const bool DEBUG = false;

inline char bin_to_hex_char(const std::string& bin) {
    if (bin == "0000") return '0';
    if (bin == "0001") return '1';
    if (bin == "0010") return '2';
    if (bin == "0011") return '3';
    if (bin == "0100") return '4';
    if (bin == "0101") return '5';
    if (bin == "0110") return '6';
    if (bin == "0111") return '7';
    if (bin == "1000") return '8';
    if (bin == "1001") return '9';
    if (bin == "1010") return 'a';
    if (bin == "1011") return 'b';
    if (bin == "1100") return 'c';
    if (bin == "1101") return 'd';
    if (bin == "1110") return 'e';
    if (bin == "1111") return 'f';
    return '0'; 
}

inline std::string binary_to_hex(const std::string& bin) {
    std::string hex;
    int length = bin.length();

    if (length % 4 != 0) {
        int padding = 4 - (length % 4);
        std::string padded_bin = std::string(padding, '0') + bin;
        length = padded_bin.length();

        for (int i = 0; i < length; i += 4) {
            hex += bin_to_hex_char(padded_bin.substr(i, 4));
        }
    } else {
        for (int i = 0; i < length; i += 4) {
            hex += bin_to_hex_char(bin.substr(i, 4));
        }
    }

    return hex;
}

inline const char* hex_char_to_bin(char c) {
	switch(toupper(c)) {
		case '0': return "0000";
		case '1': return "0001";
		case '2': return "0010";
		case '3': return "0011";
		case '4': return "0100";
		case '5': return "0101";
		case '6': return "0110";
		case '7': return "0111";
		case '8': return "1000";
		case '9': return "1001";
		case 'A': return "1010";
		case 'B': return "1011";
		case 'C': return "1100";
		case 'D': return "1101";
		case 'E': return "1110";
		case 'F': return "1111";
		default: return "0";
	}
}

inline std::string hex_to_binary(std::string hex) {
	std::string bin;
	for(unsigned i = 0; i != hex.length(); ++i)
		bin += hex_char_to_bin(hex[i]);
	return bin;
}

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH)+string("bristol_format/");

template<typename T>
void test(int party, T* io, string name, string check_output = "", string hin = "") {
	//string file = circuit_file_location + name;
	string file = name;
	BristolFormat cf(file.c_str());
	auto t1 = clock_start();
	C2PC<T> twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;

    bool *in; 
    bool *out;
    in = new bool[cf.n1 + cf.n2];
    out = new bool[cf.n3];
    if (hin.size() > 0) {
        string bin = hex_to_binary(hin);
        for (int i=0; i < cf.n1 + cf.n2; ++i) {
            if (bin[i] == '0') 
                in[i] = false;
            else if (bin[i] == '1') 
                in[i] = true;
            else {
                cout << "problem: " << bin[i] << endl;
                exit(1);
            }
        }
    } else {
        memset(in, false, cf.n1 + cf.n2);
    }
	memset(out, false, cf.n3);
	t1 = clock_start();
	twopc.online(in, out, true);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;

	if (DEBUG) {
		cout << "actual output: " << endl;
		for (int i=0; i < cf.n3; ++i)
			cout << out[i];
		cout << endl;
	}
    
	if(check_output.size() > 0){
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}
	delete[] in;
	delete[] out;
}

template<typename T>
string ag2pc_exec(int party, T* io, string name, string hin = "", string check_output = "") {
	//string file = circuit_file_location + name;
	string file = name;
	BristolFormat cf(file.c_str());
	auto t1 = clock_start();
	C2PC<T> twopc(io, party, &cf);
	io->flush();
	if (DEBUG) cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	if (DEBUG) cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	if (DEBUG) cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;

    bool *in; 
    bool *out;
    in = new bool[cf.n1 + cf.n2];
    out = new bool[cf.n3];
    if (hin.size() > 0) {
        string bin = hex_to_binary(hin);
        for (int i=0; i < cf.n1 + cf.n2; ++i) {
            if (bin[i] == '0') 
                in[i] = false;
            else if (bin[i] == '1') 
                in[i] = true;
            else {
                cout << "problem: " << bin[i] << endl;
                exit(1);
            }
        }
    } else {
        memset(in, false, cf.n1 + cf.n2);
    }
	memset(out, false, cf.n3);
	t1 = clock_start();
	twopc.online(in, out, true);
	if (DEBUG) cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;

	if (DEBUG) {
		cout << "actual output: " << endl;
		for (int i=0; i < cf.n3; ++i)
			cout << out[i];
		cout << endl;
	}
    
	string res = "";
	for(int i = 0; i < cf.n3; ++i){
		res += (out[i]?"1":"0");
	}

	if(check_output.size() > 0){
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}

	delete[] in;
	delete[] out;


	return binary_to_hex(res);
}