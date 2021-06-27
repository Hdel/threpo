import os, socket, ssl, threading
import time

import AgentHandlerThread
import DatabaseUtils
import Utilities


class SSLServer(threading.Thread):
    def run(self):
        print("reg server...")
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.load_cert_chain(certfile=os.path.dirname(__file__) + "/cert.pem",
                                keyfile=os.path.dirname(__file__) + "/key.pem")

        # listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('10.176.34.18', 9556))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssl_sock:
                while True:
                    # accept the client
                    client_socket, addr = ssl_sock.accept()
                    # start a new thread to handle it
                    print("A new agent comes, starting a RegThread for it.")
                    thread = AgentHandlerThread.AgentHandlerThreadReg(client_socket)
                    thread.start()


def server_thread(agent_pool, proxy_pool, proxy_dist):
    print("socket server...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('10.176.34.18', 7768))
        sock.listen(5)
        while True:
            client_socket, addr = sock.accept()
            thread = AgentHandlerThread.AgentHandlerThread(client_socket, addr, agent_pool, proxy_pool, proxy_dist)
            agent_pool.update({addr[0]: {"addr": addr, "thread": thread, "socket": client_socket}})
            thread.start()


def manager_thread(agent_pool, proxy_pool, proxy_dist):
    conn = DatabaseUtils.get_database_connection()
    cursor = conn.cursor()

    while True:
        time.sleep(20)
        cursor.execute("select * from config_info")
        configs_info = cursor.fetchall()

        for info in configs_info:
            config = info[0]
            section = info[1]
            value = info[2]

            if int(config.get(section, config)) != value:
                config.set(section, config, value)
                if section == "alert":
                    pass
                elif section == "interval":
                    for agent in agent_pool:
                        sock = agent_pool[agent]["socket"]
                        sock.send(str({"type": "config_changed", "info":[{"section": "interval", "config": config, "value": value}]}).encode("utf-8"))

                elif config == "if_proxy" and value == 1:
                    cursor.execute("select * from proxy_list")
                    addr_list = cursor.fetchall()

                    for addr in addr_list:
                        ip_addr = addr[0]
                        sock = agent_pool[ip_addr]["socket"]
                        sock.send(str({"type": "proxy"}).encode("utf-8"))
                        proxy_pool.update({ip_addr: agent_pool[ip_addr]["socket"]})
                        proxy_dist.update({ip_addr: []})

                    for addr in agent_pool:
                        dist_list = list(map(lambda x: (Utilities.get_distance(x, addr), x), [x for x in proxy_pool]))
                        assigned_proxy = min(dist_list)
                        assigned_proxy = assigned_proxy[1]
                        key = Utilities.random_gen()
                        proxy_dist[assigned_proxy].append({"addr": addr, "key": key, "socket": agent_pool[addr]["socket"],
                                                           "identity": agent_pool[addr]["thread"].identity})

                elif config == "if_proxy" and value == 0:
                    for proxy in proxy_pool:
                        sock = proxy_pool[proxy]["socket"]
                        sock.send(str({"type": "change_server", "new_addr": 0, "new_port": 0, "new_key": 0}).encode())
                    proxy_pool = {}
                    proxy_dist = {}

            config.write(open(os.path.dirname(__file__) + "/config.conf", "w"))


class ServerMain(threading.Thread):
    def run(self):
        agent_pool = {}
        proxy_pool = {}
        proxy_dist = {}
        thread_server = threading.Thread(target=server_thread, args=(agent_pool, proxy_pool, proxy_dist))
        thread_manager = threading.Thread(target=manager_thread, args=(agent_pool, proxy_pool, proxy_dist))

        thread_manager.start()
        thread_server.start()


