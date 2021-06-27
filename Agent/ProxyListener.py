import time
import threading

import AUtils


class ProxyListenerThread(threading.Thread):
    def __init__(self, proxy_socket, agent_pool, finish_proxy):
        threading.Thread.__init__(self)
        self.proxy_socket = proxy_socket
        self.agent_pool = agent_pool
        self.finish_proxy = finish_proxy

    def run(self):
        while True:
            reply = self.proxy_socket.recv(1024)
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
                        AUtils.set_behavior_type("agent")
                        for agent in self.agent_pool:
                            agent["socket"].send(str({"type": "change_server", "new_addr": 0,
                                                      "new_port": 0, "new_key": 0}).encode())
                        self.finish_proxy[0] = True
                        break
