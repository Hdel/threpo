import time

import sqlite3
import socket

import threading

import AUtils
import ProxyListener
import AgentMain


def proxy_main():
    addr = AUtils.get_connection()
    proxy_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    proxy_socket.connect(addr)

    proxy_socket.send(str({"type": "proxy_reg"}).encode("utf-8"))

    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute('create table agent(id, secret char(32), digest char(64), op_timestamp decimal(10, 0))')
    conn.commit()

    agent_pool = []

    while True:
        msg = proxy_socket.recv(2048).decode()
        msg = eval(msg)
        if msg["type"] == "reg_done":
            break
        cursor.execute("insert into agent (id, secret, digest, op_timestamp) values(%d, '%s', '%s', %f)" %
                       (msg["identity"], msg["secret"], msg["digest"], time.time()))

    finish_proxy = [False,]

    listener = ProxyListener.ProxyListenerThread(proxy_socket, agent_pool, finish_proxy)
    listener.start()

    server = threading.Thread(target=proxy_server, args=(agent_pool, proxy_socket, finish_proxy))
    server.start()

    listener.join()
    server.join()


def proxy_server(agent_pool, proxy_socket, finish_proxy):
    ip_addr = socket.gethostbyname(socket.gethostname())
    port = 7768

    proxy_addr = (ip_addr, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(proxy_addr)
        sock.listen(5)
        while True:
            if finish_proxy[0]:
                break

            client_socket, addr = sock.accept()
            thread = threading.Thread(target=agent_handler, args=(client_socket, proxy_socket, agent_pool, finish_proxy))
            agent_pool.append({"socket": client_socket, "thread": thread})
            thread.start()
            break


def agent_handler(client_socket, agent_pool, proxy_socket, finish_proxy):
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    start_time = time.time()
    while not finish_proxy[0]:

        cur_time = time.time()
        if cur_time-start_time > 10:
            start_time = cur_time
            if AUtils.get_hardware() == AUtils.collect_normal():
                data = AgentMain.wrap("proxy_normal", {"report": "none"})
                proxy_socket.send(data.encode("utf-8"))
            else:
                AgentMain.abnormal_report(proxy_socket)

        client_socket.recv(4096).decode("utf-8")
        if not msg:
            break
        msg = eval(msg)

        identity = msg["identity"]
        cursor.execute("select digest, secret from agent where identity=%d" % identity)
        result_1 = cursor.fetchone()
        secret, digest = result_1[1], result_1[0]

        msg_type = msg["type"]
        if msg_type == "normal":
            ret = check_integrity(msg, secret)

        elif msg_type == "confirmation":
            ret_1 = check_integrity(msg, secret)
            if ret_1 == 0:
                info = msg["info"]
                info.pop("digest")
                info.update({"secret": secret})
                if AUtils.hash_wrapper(info) == digest:
                    ret = 0
                else:
                    ret = {"status": "error", "description": "err while confirming", "identity": identity}
            else:
                ret_1.update({"identity": identity})
                ret = ret_1

            if ret != 0:
                proxy_socket.send(str(ret).encode("utf-8"))

        elif msg_type == "abnormal":
            data = AgentMain.wrap("proxy_abnormal", msg["info"], msg["identity"])
            proxy_socket.send(data.encode("utf-8"))
            ret = 0

        client_socket.send(str(ret).encode("utf-8"))

    time.sleep(5)
    client_socket.close()


def check_integrity(msg, key):
    info_dict = eval(str(msg))

    stamp = info_dict["stamp"]
    msg_time = info_dict["timestamp"]
    msg_type = info_dict["type"]
    identity = info_dict["identity"]

    valid_interval = 10

    info_dict.pop("stamp")
    info_dict.update({"secret": key})

    hex_digest = AUtils.hash_wrapper(info_dict)

    if hex_digest == stamp:
        if time.time() - msg_time <= valid_interval:
            return {"type": msg_type, "identity": identity, "status": "sound", "info": info_dict["info"]}
        return {"status": "error", "description": "time out"}
    else:
        return {"status": "error", "description": "integrity check failed"}