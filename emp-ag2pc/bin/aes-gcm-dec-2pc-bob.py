import os
import subprocess

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    
    bob_m           = "8e6414c404b7726c038baf352f86cef9"
    bob_tag         = "4b59db0dca2bb7bb01efe13f4695b566"
    bob_key_share   = "a368091b9dcc0048ba7d3f288630209a"
    bob_iv_share    = "aefb80590000000000000000"

    alice_auth_data = "0" * 26
    alice_key_share = "0"
    alice_iv_share  = "0"
    
    len_c_i = len(bob_m) * 4
    len_a_i = len(alice_auth_data) * 4

    host = "127.0.0.1"

    cmd = f"./test_aes-gcm-dec-2pc {str(party)} {str(port)} {bob_m} {bob_tag} {bob_key_share} {bob_iv_share} {alice_auth_data} {alice_key_share} {alice_iv_share} {str(len_c_i)} {str(len_a_i)} {host}"
    print(f"cmd: {cmd}")
    
    output = subprocess.check_output(cmd, shell=True)
    output_str = output.decode("utf-8")
    print(f"!output: {output_str}")
    outputs = output_str.split('\n')
    print(outputs)
    cipher, tag = outputs[-3], outputs[-2]

    print(f"get cipher 0x{cipher}")
    print(f"get tag    0x{tag}")