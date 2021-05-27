import time
from configparser import ConfigParser
import threading
import pymysql


class DatabaseThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        config = ConfigParser()
        config.read("config.conf")
        check_interval = int(config.get("interval", "check_exist"))
        host = config.get("mysql", "host")
        port = config.get("mysql", "port")
        database = config.get("mysql", "database")
        username = config.get("mysql", "username")
        password = config.get("mysql", "password")
        conn = pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)

        time.sleep(20)
        while True:
            cursor = conn.cursor()
            cursor.execute("select id from machines where (state = 0 or state = 1) and %f-update_time > %d" % (time.time(), check_interval))
            obj_list = cursor.fetchall()
            log_insert = "insert into change_log (operation, description, op_timestamp, witness) values (%d, '%s', %f, %d)"
            for item in obj_list:
                cursor.execute(log_insert % (4,'machines'+'@'+str(item[0])+'@'+str(item[0]), time.time(), 0))
            conn.commit()
            conn.close()
            time.sleep(check_interval)

