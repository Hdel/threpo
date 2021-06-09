import re
import telnetlib
import threading
import time
from configparser import ConfigParser

import pymysql

switch_list = dict()


def get_db_conn():
    config = ConfigParser()
    ret = config.read("C:\\Users\\Hester\\Desktop\\thesis\\th1\\Server\\config.conf")
    host = config.get("mysql", "host")
    port = config.get("mysql", "port")
    database = config.get("mysql", "database")
    username = config.get("mysql", "username")
    password = config.get("mysql", "password")
    conn = pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)
    return conn


def refresh_switch_list():
    switch_list.clear()

    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("select * from switch_table")
    switches = cursor.fetchall()

    for switch in switches:
        switch_list[switch[1]] = (switch[0], switch[2], switch[3], switch[4], switch[5])

    conn.close()


class TelnetSwitchBrocade(object):
    def __init__(self, telnetIp, passwd):
        self.tnconn = telnetlib.Telnet(telnetIp)
        self.tnconn.read_until('Password: ')
        self.tnconn.write(passwd + '\r\n')
        time.sleep(1)

    def __del__(self):
        self.tnconn.close()

    def get_interface_status(self):
        self.tnconn.write('show interfaces\n')
        time.sleep(2)
        result = self.tnconn.read_very_eager()

        if '--More--' in result:
            result = result.replace('--More--\n', '')

            while True:
                self.tnconn.write(' ')
                time.sleep(0.5)
                next_result = self.tnconn.read_very_eager()

                result = result.replace('\x08\x08', '')
                result = result.replace('--More--\n', '')
                result += next_result

                if '--More--' not in next_result:
                    break

        result_list = result.split("\n")
        for r in result_list:
            r.strip()

        # for r in result_list:
        #     print(r)

        new_result = []

        pattern_include = r'([\w]+[0-9]+/[0-9]+/[0-9])+ is up'

        print(result_list)

        for r in result_list:
            temp = ""
            for j in r:
                if j.isalnum() or j in "-/ ":
                    temp += j
            temp.strip()
            search_ret = re.search(pattern_include, temp)
            if search_ret is not None:
                new_result.append((search_ret.group(1), "up"))
                continue

        return new_result


class TelnetSwitch(object):
    def __init__(self, telnetIp, uname, passwd):
        self.tnconn = telnetlib.Telnet(telnetIp)
        self.tnconn.read_until('login:')
        self.tnconn.write(uname + '\n')
        self.tnconn.read_until('Password: ')
        self.tnconn.write(passwd + '\n')
        time.sleep(1)

    def __del__(self):
        self.tnconn.close()

    def get_interface_status(self):
        self.tnconn.write('show interface status\n')
        time.sleep(2)
        result = self.tnconn.read_very_eager()

        if '--More--' in result:
            result = result.replace('--More--\n', '')

            while True:
                self.tnconn.write(' ')
                time.sleep(1)
                next_result = self.tnconn.read_very_eager()

                result = result.replace('--More--\n', '')
                result += next_result

                if '--More--' not in next_result:
                    break

        result_list = result.split("\n")
        for r in result_list:
            r.strip()

        # for r in result_list:
        #     print(r)

        result_list = result_list[12:-1]

        new_result = []

        pattern_exclude = r'[\w]+[\s]+[0-9]+/[0-9]+/[0-9]+[\s]+sfpAbsent'
        pattern_include = r'([\w]+[\s]+[0-9]+/[0-9]+/[0-9]+)[\s]+[\S]+[\s]+[\S]+[\s]+[\S]+[\s]+([\S]+)'

        for r in result_list:
            temp = ""
            for j in r:
                if j.isalnum() or j in "-/ ":
                    temp += j
            temp.strip()
            search_ret = re.search(pattern_exclude, temp)
            if search_ret is None:
                search_ret = re.search(pattern_include, temp)
                if search_ret is not None:
                    new_result.append((search_ret.group(1), search_ret.group(2)))
                continue

        return new_result


class SwitchCheckHandler(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        refresh_switch_list()
        self.conn = get_db_conn()
        cursor = self.conn.cursor()
        for switch in switch_list:
            sql_str = "create table if not exists switch_%d (interface varchar (40), status varchar (255))"
            cursor.execute(sql_str % switch_list[switch][0])
            self.conn.commit()

    def run(self):
        conn = self.conn
        cursor = self.conn.cursor()
        while True:
            for switch in switch_list:
                # if switch_list[switch][5] == "Cisco":
                #     results = TelnetSwitch().get_interface_status(switch, switch_list[switch][2], switch_list[switch][3])
                # elif switch_list[switch][5] == "Brocade":
                #     results = TelnetSwitchBrocade().get_interface_status(switch, switch_list[switch][3])
                results = [('Fo 4/0/49', '40G-QSFP'), ('Fo 4/0/50', '40G-QSFP'), ('Te 4/0/1', '10G-SFP-SR'), ('Te 4/0/2', '10G-SFP-SR'), ('Te 4/0/3', '10G-SFP-SR'), ('Te 4/0/4', '10G-SFP-SR'), ('Te 4/0/5', '10G-SFP-SR'), ('Te 4/0/6', '10G-SFP-SR'), ('Te 4/0/7', '10G-SFP-SR'), ('Te 4/0/8', '10G-SFP-SR'), ('Te 4/0/9', '10G-SFP-SR'), ('Te 4/0/10', '10G-SFP-SR'), ('Te 4/0/11', '10G-SFP-SR'), ('Te 4/0/12', '10G-SFP-SR'), ('Te 4/0/13', '10G-SFP-SR'), ('Te 4/0/14', '10G-SFP-SR'), ('Te 4/0/15', '10G-SFP-SR'), ('Te 4/0/16', '10G-SFP-SR'), ('Te 4/0/17', '10G-SFP-SR'), ('Te 4/0/23', '10G-SFP-SR'), ('Te 4/0/24', '10G-SFP-SR')]
                results.sort()
                check_dict = dict()

                for result in results:
                    check_dict[result[0]] = result[1]

                switch_id = switch_list[switch][0]

                table = "switch_"+str(switch_list[switch][0])
                cursor.execute("select * from %s" % table)
                stored = list(cursor.fetchall())
                insert_sql = "insert into change_log (operation, description, op_timestamp, witness) values (%d, " \
                             "'%s', %f, %d) "

                if len(stored) == 0:
                    cursor.execute(insert_sql % (7, table, time.time(), 0))

                stored.sort()
                stored_dict = dict()

                cursor.execute("truncate table %s" % table)

                for result in stored:
                    stored_dict[result[0]] = result[1]

                for interface in check_dict:
                    if interface not in stored_dict:
                        cursor.execute(insert_sql % (10, table+"@"+interface+"@"+check_dict[interface], time.time(), 0))
                    elif stored_dict[interface] != check_dict[interface]:
                        cursor.execute(insert_sql % (9, table+"@"+interface+"@"+stored_dict[interface], time.time(), 0))
                        cursor.execute(insert_sql % (10, table+"@"+interface+"@"+check_dict[interface], time.time(), 0))
                        stored_dict.pop(interface)
                    elif stored_dict[interface] == check_dict[interface]:
                        stored_dict.pop(interface)

                for left_interface in stored_dict:
                    cursor.execute(insert_sql % (9, table+"@"+left_interface+"@"+stored_dict[left_interface], time.time(), 0))

                cursor.executemany("insert into "+ table + " (interface, status) values (%s, %s)", args=results)
                cursor.execute("update switch_table set op_timestamp = %f where id = %d" %
                               (time.time(), switch_id))
                conn.commit()
            break


handler_s = SwitchCheckHandler()
handler_s.start()