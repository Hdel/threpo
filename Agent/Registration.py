import socket, os, ssl

import AUtils

from configparser import ConfigParser

ssl_server = "10.176.34.18"
ssl_port = 9556


def ssl_registration():
    print("registration...")
    config = ConfigParser()
    config.read(os.path.dirname(__file__) + "/agent.conf")
    identity = int(config.get("whoami", "identity"))

    # if not registered, the identity of the agent is by default -1
    if int(identity) == -1:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(s, ca_certs=os.path.dirname(__file__) + "/cert/cert.pem",
                                   cert_reqs=ssl.CERT_REQUIRED)
        ssl_sock.connect((ssl_server, ssl_port))

        # collect basic information of the agent
        info = AUtils.collect_normal()
        data, key = AUtils.wrap_reg(info)

        # send registration information the server
        ssl_sock.send(data.encode("utf-8"))
        reg_result = int(ssl_sock.recv(1024))
        ssl_sock.close()

        config.set("whoami", "identity", str(reg_result))
        config.set("whoami", "key", key)
        config.set("whoami", "backup_key", key)

        config.write(open(os.path.dirname(__file__) + "/agent.conf", "w"))

        AUtils.set_hardware(info)
        return 0
    else:
        return 1
