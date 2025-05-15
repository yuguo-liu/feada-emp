import os
import subprocess

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    
    bob_m         = "0" * 320
    bob_key_share = "0"
    bob_iv_share  = "0"

    alice_m         = "00000000000000000000000000000000ac26bf1a9926001a37d5eb22a8695817736f85e6ef54b2c37e5923a6d8134b2b51f59ac31da2ed7e8bbbb70474b2c21815a276ab193b5fc3477db1c3e740d96bc5658b5fb3f041fbfcd609c79989660f66aba44631d57b43b279f9324de87a82a9c25baf5ba871d76882a0db4b409f0a2458453af765ef5a416d26da4a4cdb1ecdde02301eefbdbab81c04e347fcafbd"
    alice_auth_data = "01020304050607080900"
    alice_key_share = "0102030405060708090a0b0c0d0e0f00"
    alice_iv_share  = "0102030405060708090a0b0c"
    r_com           = "8dd1485d13f3728ec81f2fab68c304b3"
    commitment      = "592e332c40056a34e250f4a0ba579980db85c24ede7ba66b09b67ccee100a65d"
    
    len_c_i = len(bob_m) * 4
    len_a_i = len(alice_auth_data) * 4

    host = "127.0.0.1"

    cmd = f"./test_predicate-aes-gcm-2pc {str(party)} {str(port)} {bob_m} {bob_key_share} {bob_iv_share} {alice_m} {alice_auth_data} {alice_key_share} {alice_iv_share} {r_com} {commitment} {str(len_c_i)} {str(len_a_i)} {host}"
    print(f"cmd: {cmd}")
    
    output = subprocess.check_output(cmd, shell=True)
    output_str = output.decode("utf-8")
    print(f"!output: {output_str}")
    outputs = output_str.split('\n')
    print(outputs)
    cipher, tag = outputs[-3], outputs[-2]

    print(f"get cipher 0x{cipher}")
    print(f"get tag    0x{tag}")