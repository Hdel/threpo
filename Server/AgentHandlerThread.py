import threading
import time

import AgentHandlerHelper
import DatabaseUtils
import Utilities


class AgentHandlerThreadReg(threading.Thread):
    def __init__(self, client_sock, agent_pool, proxy_pool):
        threading.Thread.__init__(self)
        self.client_socket = client_sock

    def run(self):
        msg = eval(self.client_socket.recv(4096).decode("utf-8"))
        print(msg)
        conn = DatabaseUtils.get_database_connection()
        ret_id = AgentHandlerHelper.registration(conn, msg)
        print("coming agent id: %d" % ret_id)
        self.client_socket.send(str(ret_id).encode("utf-8"))

    def __del__(self):
        self.client_socket.close()


class AgentHandlerThread(threading.Thread):
    key = -1
    is_settled = False
    identity = -1

    def __init__(self, client_sock, addr, agent_pool, proxy_pool, proxy_dist):
        threading.Thread.__init__(self)
        self.client_socket = client_sock
        self.client_addr = addr
        self.conn = DatabaseUtils.get_database_connection()
        self.agent_pool = agent_pool
        self.proxy_pool = proxy_pool
        self.proxy_dist = proxy_dist

    def run(self):
        cursor = self.conn.cursor()
        while True:
            msg = self.client_socket.recv(4096).decode("utf-8")

            if not msg:
                break

            msg = eval(msg)

            if not self.is_settled:
                self.key = Utilities.get_key_by_id(self.conn, msg["identity"])
                self.is_settled = True
                self.identity = msg["identity"]

            msg_type = msg["type"]
            if msg_type == "normal":
                ret = AgentHandlerHelper.normal(msg, self.key)

            elif msg_type == "confirmation":
                ret = AgentHandlerHelper.confirmation(self.conn, msg, self.key)

            elif msg_type == "abnormal":
                ret = AgentHandlerHelper.abnormal(self.conn, msg, self.key)

            elif msg_type == "proxy_reg":
                time.sleep(20)
                self.key = Utilities.get_key_by_id(self.conn, msg["identity"])
                self.is_settled = True
                self.identity = msg["identity"]
                for entry in self.proxy_dist[self.client_addr[0]]:
                    agent_sock = entry["socket"]
                    agent_sock.send(str({"type": "change_server", "new_addr": self.client_addr[0], "new_port": 9556,
                                         "new_key": DatabaseUtils.get_digest_by_id(self.conn, entry["identity"])}).encode("utf-8"))
                    self.client_socket.send(str({"type": "agent_info", "secret": DatabaseUtils.get_digest_by_id(self.conn, entry["identity"]),
                                                 "digest": DatabaseUtils.get_digest_by_id(self.conn, entry["identity"]),
                                                 "identity": entry["identity"]}).encode("utf-8"))

                data = {"type": "reg_done"}
                self.client_socket.send(str(data).encode("utf-8"))
                ret = 0
                pass

            elif msg_type == "proxy_abnormal":
                for entry in self.proxy_dist[self.client_addr[0]]:
                    if entry["identity"] == msg["identity"]:
                        key = entry["key"]
                        AgentHandlerHelper.abnormal(self.conn, msg, key)
                        break
                ret = 0

            elif msg_type == "proxy_normal":
                ret = AgentHandlerHelper.normal(msg, self.key)
                agent_list = list(map(lambda x: x["identity"], [x for x in self.proxy_dist[self.client_addr[0]]]))
                DatabaseUtils.update_list(conn=self.conn, agent_list=agent_list)

            elif msg_type == "proxy_error":
                DatabaseUtils.insert_abnormal(msg, self.conn, msg["identity"])
                ret = 0

            else:
                ret = {"status": "error", "description": "no such type."}

            cursor.execute("update machines set update_time=%f where id=%d" % (time.time(), self.identity))

            if ret != 0:
                DatabaseUtils.insert_abnormal(ret, self.conn, self.identity)

            self.client_socket.send(str(ret).encode("utf-8"))

    def __del__(self):
        self.client_socket.close()
        self.agent_pool.pop(self.client_addr[0])
        self.conn.close()

