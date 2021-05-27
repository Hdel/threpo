import socket
import ssl
import threading
import utilities
import database_ops as dbop
import DatabaseThread


class HandlerThread(threading.Thread):
    key_settled = False
    thread_key = 0

    # save ssl_socket information
    def __init__(self, client_sock, addr):
        threading.Thread.__init__(self)
        self.client_socket = client_sock
        self.client_addr = addr

    def run(self):
        print("start thread")
        while True:
            msg = self.client_socket.recv(4096).decode("utf-8")
            if not msg:
                break

            # unwrap the message
            # format:
            # "type": str, "identity": int, "status": str, "info":dict
            result = utilities.unwrap(msg, self.thread_key)
            if result["status"] == "sound":
                print(f"receive msg from client {self.client_addr}：{msg}")
                if (not self.key_settled) and result["type"] == "confirmation":
                    self.thread_key = dbop.Actions().get_comm_key(result["identity"])
                    self.key_settled = True
                new_msg = str(self.parse(result))
                self.client_socket.send(new_msg.encode("utf-8"))

            # integrity check failed
            # or timeout
            # todo: write error to the log
            else:
                print(result["status"] + ': ' + result["description"])
                self.client_socket.send(str(1).encode("utf-8"))

    def parse(self, result):
        # redirect to different functions
        method_dict = {
            "registration": dbop.Actions().registration,
            "confirmation": dbop.Actions().confirmation,
            "normal": normal_check,
            "abnormal": abnormal_check,
        }
        # print(result)
        msg_type = result["type"]
        return method_dict.get(msg_type)(result)

    # when thread is destroyed
    # close the ssl_socket
    def __del__(self):
        print("thread del called here")
        self.client_socket.close()


class ServerSSL:
    def build_listen(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

        # listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', 9556))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    # accept the client
                    client_socket, addr = ssock.accept()
                    # start a new thread to handle it
                    thread = HandlerThread(client_socket, addr)
                    thread.start()


def normal_check(result):
    try:
        if result["info"]["report"] == "none":
            return 0
        else:
            return 1
    except IndexError:
        return 2


def abnormal_check(result):
    abnormal_list = result["info"]["abnormal_list"]
    old_list = result["info"]["old_list"]
    identity = result["identity"]
    del_list = []
    insert_list = []

    # check if provided old_list is authentic
    if dbop.Actions().check_digest(identity, old_list):
        # drop different changes into different categories(list)
        # change old_list based on provided abnormal list
        print("check1")

        for entry in abnormal_list:
            # if this resource is deleted
            if entry["abnormal_type"] == 3:
                insert_list.append({"res_type": entry["res_type"], "content": entry["description"]})
                old_list[entry["res_type"]].append(entry["description"])
            # if a new resource added
            elif entry["abnormal_type"] == 2:
                del_list.append({"res_type": entry["res_type"], "content": entry["description"]})
                old_list[entry["res_type"]].remove(entry["description"])

        # check if changes provided matches with new hash digest
        new_digest = result["info"]["new_digest"]
        for entry in old_list:
            old_list[entry].sort(key=str)
        calculated_digest, fetched_digest = dbop.Actions().cal_digest(identity, old_list)

        if new_digest == calculated_digest:
            dbop.Actions().abnormal_update(identity, del_list, insert_list, new_digest)
            return 0
    dbop.Actions().integrity_failed_log(identity)
    return 1


if __name__ == "__main__":
    db_thread = DatabaseThread.DatabaseThread()
    db_thread.start()
    server = ServerSSL()
    server.build_listen()
