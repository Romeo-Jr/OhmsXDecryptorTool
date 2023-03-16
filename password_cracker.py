import hashlib
import argparse
import sys
import os

from Tool.hash_type import Encrypt

from colorama import Fore, init
init(autoreset=True)

#BANNER
BANNER = """
   ____  __                  _  __    ____                             __                ______            __
  / __ \/ /_  ____ ___  ____| |/ /   / __ \___  ____________  ______  / /_____  _____   /_  __/___  ____  / /
 / / / / __ \/ __ `__ \/ ___/   /   / / / / _ \/ ___/ ___/ / / / __ \/ __/ __ \/ ___/    / / / __ \/ __ \/ / 
/ /_/ / / / / / / / / (__  )   |   / /_/ /  __/ /__/ /  / /_/ / /_/ / /_/ /_/ / /       / / / /_/ / /_/ / /  
\____/_/ /_/_/ /_/ /_/____/_/|_|  /_____/\___/\___/_/   \__, / .___/\__/\____/_/       /_/  \____/\____/_/   
                                                       /____/_/                                              
"""

HEADER_CONTENT = """
    Author : Romeo Delacruz Estoy Jr
    Version : 1.0
    Module : hashlib

    HASH TYPE

    [1] Sha1
    [2] Sha384
    [3] Sha224
    [4] Blake2b
    [5] Blake2s
    [6] Md5

---------------------------------------------------------------------------
"""

# INITIALIZE PARSER
APP_DESC = """
    OhmsX Decryptor a simple tool that can decrypt hash text.
"""

#ARGPARSE
parser = argparse.ArgumentParser(description=APP_DESC)

parser.add_argument("hash", type = str, nargs=1, help="Hash String")
parser.add_argument("wordlist", type = str, nargs=1, help="Wordlist use to crack the hash")

parser.add_argument("-hT","--hash_type", type = int, nargs = 1, metavar = "", required = True, help = "Type of Hash", choices = range(1,7))
parser.add_argument("-uS","--use_salts", type = int, nargs = 1, metavar = "", required = True, help = "0 or 1. Default is 0", choices = [0, 1])
parser.add_argument("-sF","--file_salts", type = str, nargs = 1, metavar = "", help = "File that contains salts text")

args = parser.parse_args()

def crack_hash(hash, use_salts):

    index_cracked_pass = -1  

    if use_salts == 1:
        """
        HASH TYPE 

        1 = sha1
        2 = sha384
        3 = sha224
        4 = blake2b
        5 = blake2s
        6 = md5
        """
        try:
            with open(args.file_salts[0], "r") as salt_file:
                salt_data = salt_file.readlines()
                for salt_index in range(len(salt_data)):
                    try:
                        with open(args.wordlist[0], "r") as plain_file:
                            plain_data = plain_file.readlines()
                            for plain_i in range(len(plain_data)):
                                text = salt_data[salt_index].strip() + plain_data[plain_i].strip()
                                match args.hash_type[0]:
                                    case 1:
                                        hashed_data = Encrypt(text).hash_sha1()
                                        if hashed_data == hash:
                                            index_cracked_pass += plain_i
                                            cracked_pass = plain_data[index_cracked_pass+1].strip()
                                    case 2:
                                        hashed_data = Encrypt(text).hash_sha384()
                                        if hashed_data == hash:
                                            index_cracked_pass += plain_i
                                            cracked_pass = plain_data[index_cracked_pass+1].strip()
                                    case 3:
                                        hashed_data = Encrypt(text).hash_sha224()
                                        if hash == hashed_data:
                                            index_cracked_pass += plain_i
                                            cracked_pass = plain_data[index_cracked_pass+1].strip()
                                    case 4:
                                        hashed_data = Encrypt(text).hash_blake2b()
                                        if hash == hashed_data:
                                            index_cracked_pass += plain_i
                                            cracked_pass = plain_data[index_cracked_pass+1].strip()
                                    case 5:
                                        hashed_data = Encrypt(text).hash_blake2s()
                                        if hash == hashed_data:
                                            index_cracked_pass += plain_i
                                            cracked_pass = plain_data[index_cracked_pass+1].strip()
                                    case 6:
                                        hashed_data = Encrypt(text).hash_md5()
                                        if hash == hashed_data:
                                            index_cracked_pass += plain_i
                                            cracked_pass = plain_data[index_cracked_pass+1].strip()

                    except Exception as e:
                        print(Fore.RED + f"No such file or Directory : {args.wordlist[0]}")
                        sys.exit()

                if index_cracked_pass == -1:
                    return Fore.RED + f"{args.hash[0]} : Password not Found"
                else:
                    return Fore.GREEN + f"{args.hash[0]} : {cracked_pass} : Password Found"
                
        except Exception as e:
            print(Fore.RED + f"No such file or Directory : {args.wordlist[0]}")
            sys.exit()
            

    elif use_salts == 0:
        """
        HASH TYPE 

        1 = sha1
        2 = sha384
        3 = sha224
        4 = blake2b
        5 = blake2s
        6 = md5
        """
        try:
            with open(args.wordlist[0], "r") as file:
                data = file.readlines()
                for index in range(len(data)):
                    match args.hash_type[0]:
                        case 1:
                            hashed_data = Encrypt(data[index].strip()).hash_sha1()
                            if hash == hashed_data:
                                index_cracked_pass += index
                                cracked_pass = data[index_cracked_pass+1].strip()
                        case 2:
                            hashed_data = Encrypt(data[index].strip()).hash_sha384()
                            if hash == hashed_data:
                                index_cracked_pass += index
                                cracked_pass = data[index_cracked_pass+1].strip()
                        case 3:
                            hashed_data = Encrypt(data[index].strip()).hash_sha224()
                            if hash == hashed_data:
                                index_cracked_pass += index
                                cracked_pass = data[index_cracked_pass+1].strip()
                        case 4:
                            hashed_data = Encrypt(data[index].strip()).hash_blake2b()
                            if hash == hashed_data:
                                index_cracked_pass += index
                                cracked_pass = data[index_cracked_pass+1].strip()
                        case 5:
                            hashed_data = Encrypt(data[index].strip()).hash_blake2s()
                            if hash == hashed_data:
                                index_cracked_pass += index
                                cracked_pass = data[index_cracked_pass+1].strip()
                        case 6:
                            hashed_data = Encrypt(data[index].strip()).hash_md5()
                            if hash == hashed_data:
                                index_cracked_pass += index
                                cracked_pass = data[index_cracked_pass+1].strip()

        except Exception:
            print(Fore.RED + f"No such file or Directory : {args.wordlist[0]}")
            sys.exit()

            
        if index_cracked_pass == -1:
            return Fore.RED + f"{hash} : Password not Found"
        else:
            return Fore.GREEN + f"{hash} : {cracked_pass} : Password Found"

if __name__ == '__main__':
    os.system('cls')
    
    print(Fore.RED + BANNER)
    print(HEADER_CONTENT)
    
    if args.use_salts[0] == 0:
        print(crack_hash(args.hash[0], 0 ))
    else:
        print(crack_hash(args.hash[0], 1 )) 
    
      