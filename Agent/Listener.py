import time

import threading, socket
import AUtils


class ListenerThread(threading.Thread):
    def __init__(self, agent_socket):
        threading.Thread.__init__(self)
        self.agent_socket = agent_socket

    def run(self):
        while True:
            reply = self.agent_socket.recv(1024)
            reply = eval(str(reply.decode()))

            if type(reply) == int:
                print("everything is alright")
            else:
                if "status" in reply:
                    print(str(reply))
                    AUtils.set_behavior_type("error")
                else:
                    msg_type = reply["type"]
                    if msg_type == "change_server":
                        new_addr = reply["new_addr"]
                        AUtils.set_server_proxy(new_addr)
                        AUtils.set_key_proxy(reply["new_key"])
                        AUtils.set_behavior_type("change_server")
                        time.sleep(10)
                        break
                    elif msg_type == "config_changed":
                        change_list = reply["info"]
                        for entry in change_list:
                            config = entry["section"]
                            value = entry["value"]
                            AUtils.set_interval(config, value)
                    elif msg_type == "proxy":
                        AUtils.set_behavior_type("proxy")
                        break

