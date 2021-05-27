import hashlib

import pymysql
from configparser import ConfigParser
import time

# CREATE TABLE `change_log` (
# 	`id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
# 	`operation` smallint(5) UNSIGNED NULL,
# 	`description` varchar(200) CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
# 	`op_timestamp` decimal(10,0)  NULL,
# 	`witness` int(10) UNSIGNED NULL,
# 	PRIMARY KEY (`id`)
# ) ENGINE=InnoDB
# DEFAULT CHARACTER SET=utf8 COLLATE=utf8_general_ci
# ROW_FORMAT=DYNAMIC
# AVG_ROW_LENGTH=0;


class Actions:
    cpu_insert = "insert into cpu_info (machine, caption, core) values (%d, '%s', %d)"
    ram_insert = "insert into ram_info (machine, size, manufacturer, sn) values (%d, %d, '%s', '%s')"
    disk_insert = "insert into disk_info (machine, size, caption, sn) values (%d, %d, '%s', '%s')"
    nic_insert = "insert into nic_info (machine, mac) values (%d, '%s')"
    gcard_insert = "insert into gcard_info (machine,caption) values (%d, '%s')"
    machine_insert = "insert into machines (secret, digest, state, update_time) values ('%s', '%s', %d, %f)"
    log_insert = "insert into change_log (operation, description, op_timestamp, witness) values (%d, '%s', %f, %d)"

    def __init__(self):
        config = ConfigParser()
        config.read("config.conf")
        host = config.get("mysql", "host")
        port = config.get("mysql", "port")
        database = config.get("mysql", "database")
        username = config.get("mysql", "username")
        password = config.get("mysql", "password")
        self.conn = pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)

    def registration(self, msg):
        conn = self.conn
        cursor = conn.cursor()

        info_dict = msg["info"]
        secret = msg["info"]["secret"]

        # info_dict is like:
        # {'cpu_info': [{'name': 'Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz', 'core': 1}], 'ram_info': [{'size': 1993,
        # 'manufacturer': 'not retrieved', 'sn': 'not retrieved'}], 'disk_info': [{'name': 'VBOX HARDDISK',
        # 'sn': 'VBaec0675e-06b568b', 'size': 20}], 'nic_info': ['08:00:27:f2:3f:3b'], 'gcard_info': ['VMware SVGA II
        # Adapter'], 'secret': '2xXluVPBc5mEoz4K332psmcFGROU1a16'}
        sha256_hash = hashlib.sha256()
        sha256_hash.update(str(info_dict).encode("utf-8"))
        digest = sha256_hash.hexdigest()

        try:
            cursor.execute(self.machine_insert % (secret, digest, 0, time.time()))
            ret_id = conn.insert_id()
            cursor.execute(self.log_insert % (0, "new_machine" + '@' + str(ret_id) + '@' + str(ret_id), time.time(), 0))

            # insert cpu_info
            # extract cpu_info
            cpu_info = info_dict['cpu_info']
            # here might be several cpus
            for i in range(len(cpu_info)):
                # "insert into cpu_info (machine, caption, cores) values (%d, '%s', %d)"
                # 'cpu_info': [{'name': 'Intel(R) Core(TM) i5-8300H CPU @ 2.30GHz', 'core': 1}]
                cpu_item = cpu_info[i]
                cursor.execute(self.cpu_insert % (ret_id, cpu_item['name'], cpu_item['core']))
                item_id = conn.insert_id()
                cursor.execute(self.log_insert % (3, "cpu_info" + '@' + str(item_id) + '@' + str(ret_id), time.time(), 0))
            # insert ram_info
            ram_info = info_dict['ram_info']
            for i in range(len(ram_info)):
                # "insert into ram_info (machine, size, manufacturer, sn) values (%d, %d, '%s', '%s')"
                # 'ram_info': [{'size': 1993, 'manufacturer': 'not retrieved', 'sn': 'not retrieved'}]
                ram_item = ram_info[i]
                cursor.execute(self.ram_insert % (ret_id, ram_item['size'], ram_item['manufacturer'], ram_item['sn']))
                item_id = conn.insert_id()
                cursor.execute(self.log_insert % (3, "ram_info" + '@' + str(item_id) + '@' + str(ret_id), time.time(), 0))

            # insert disk_info
            disk_info = info_dict['disk_info']
            for i in range(len(disk_info)):
                # "insert into disk_info (machine, size, caption, sn) values (%d, %d, '%s', '%s')"
                # 'disk_info': [{'name': 'VBOX HARDDISK', 'sn': 'VBaec0675e-06b568b', 'size': 20}]
                disk_item = disk_info[i]
                cursor.execute(self.disk_insert % (ret_id, disk_item['size'], disk_item['name'], disk_item['sn']))
                item_id = conn.insert_id()
                cursor.execute(self.log_insert % (3, "disk_info" + '@' + str(item_id) + '@' + str(ret_id), time.time(), 0))

            # insert nic_info
            nic_info = info_dict['nic_info']
            for i in range(len(nic_info)):
                # "insert into nic_info (machine, mac) values (%d, '%s')"
                cursor.execute(self.nic_insert % (ret_id, nic_info[i]))
                item_id = conn.insert_id()
                cursor.execute(self.log_insert % (3, "nic_info" + '@' + str(item_id) + '@' + str(ret_id), time.time(), 0))

            # gcard_insert = "insert into gcard_info (machine,caption) values (%d, '%s')"
            gcard_info = info_dict['gcard_info']
            for i in range(len(gcard_info)):
                cursor.execute(self.gcard_insert % (ret_id, gcard_info[i]))
                item_id = conn.insert_id()
                cursor.execute(self.log_insert % (3, "gcard_info" + '@' + str(item_id) + '@' + str(ret_id), time.time(), 0))

            self.conn.commit()
        except:
            # rollback
            self.conn.rollback()
            return "-1"

        return str(ret_id)

    def check_digest(self, identity, info):
        calculated_digest, fetched_digest = self.cal_digest(identity, info)
        if calculated_digest == fetched_digest:
            return True
        else:
            return False

    def cal_digest(self, identity, info):
        conn = self.conn
        cursor = conn.cursor()
        cursor.execute("select digest, secret from machines where id=%d" % identity)

        fetched = cursor.fetchone()

        fetched_digest = fetched[0]
        fetched_secret = fetched[1]
        info.update({"secret": fetched_secret})

        hash_obj = hashlib.sha256()
        hash_obj.update(str(info).encode("utf-8"))
        calculated_digest = hash_obj.hexdigest()
        info.pop("secret")

        return calculated_digest, fetched_digest

    def confirmation(self, msg):
        # identity then used to fetch data of machine from database
        identity = msg["identity"]
        digest = msg["info"]["digest"]
        info_dict = msg["info"]
        info_dict.pop("digest")

        # if matches, fetch stored hash digest from database
        # and check if it matches with submitted hash
        conn = self.conn
        cursor = conn.cursor()
        cursor.execute("select digest, secret from machines where id=%d" % identity)

        fetched = cursor.fetchone()

        fetched_digest = fetched[0]
        fetched_secret = fetched[1]
        info_dict.update({"secret": fetched_secret})

        # calculate the digest
        # check if machine's hardware information matches with provided hash digest
        hash_obj = hashlib.sha256()
        hash_obj.update(str(info_dict).encode("utf-8"))
        calculated_digest = hash_obj.hexdigest()

        try:
            cursor.execute("update machines set update_time = %f where id = %d" % (time.time(), identity))
            self.conn.commit()
            print("commit...")
        except:
            self.conn.rollback()
            return 3

        # agent wrong digest calculation
        if digest != calculated_digest:
            return 1

        # agent different from server
        if fetched_digest != digest:
            return 2

        return 0

    def get_comm_key(self, identity):
        conn = self.conn
        cursor = conn.cursor()
        cursor.execute("select secret from machines where id=%d" % identity)
        key = cursor.fetchone()

        return key[0]

    def collect_info(self, identity):
        pass

    def abnormal_update(self, identity, del_list, insert_list, new_digest):
        conn = self.conn
        cursor = conn.cursor()
        print("db_update")
        for item in del_list:
            if item["res_type"] == "cpu_info":
                sql_select = "select id from cpu_info where machine=%d and caption='%s' and core=%d order by id limit 1"
                cursor.execute(sql_select % (identity, item["content"]["name"], item["content"]["core"]))
                target_id = cursor.fetchone()[0]
                sql_query = "update cpu_info set machine=-1 where machine=%d and caption='%s' and core=%d order by id limit 1"
                cursor.execute(sql_query % (identity, item["content"]["name"], item["content"]["core"]))

            elif item["res_type"] == "ram_info":
                sql_select = "select id from ram_info where machine=%d and size=%d and manufacturer='%s' and sn='%s' order by id limit 1"
                cursor.execute(sql_select % (identity, item["content"]["size"], item["content"]["manufacturer"], item["content"]["sn"]))
                target_id = cursor.fetchone()[0]
                sql_query = "update ram_info set machine=-1 where machine=%d and size=%d and manufacturer='%s' and sn='%s' order by id limit 1"
                cursor.execute(sql_query % (identity, item["content"]["size"], item["content"]["manufacturer"], item["content"]["sn"]))

            elif item["res_type"] == "disk_info":
                sql_select = "select id from disk_info where machine=%d and size=%d and caption='%s' and sn='%s' order by id limit 1"
                cursor.execute(sql_select % (identity, item["content"]["size"], item["content"]["name"], item["content"]["sn"]))
                target_id = cursor.fetchone()[0]
                sql_query = "update disk_info set machine=-1 where machine=%d and size=%d and caption='%s' and sn='%s' order by id limit 1"
                cursor.execute(sql_query % (identity, item["content"]["size"], item["content"]["name"], item["content"]["sn"]))

            elif item["res_type"]== "nic_info":
                sql_select = "select id from nic_info where machine=%d and mac='%s' order by id limit 1"
                cursor.execute(sql_select % (identity, item["content"]))
                target_id = cursor.fetchone()[0]
                sql_query = "update nic_info set machine=-1 where machine=%d and mac='%s' order by id limit 1"
                cursor.execute(sql_query % (identity, item["content"]))

            elif item["res_type"]== "gcard_info":
                sql_select = "select id from nic_info where machine=%d and caption='%s' order by id limit 1"
                cursor.execute(sql_select % (identity, item["content"]))
                target_id = cursor.fetchone()[0]
                sql_query = "update nic_info set machine=-1 where machine=%d and caption='%s' order by id limit 1"
                cursor.execute(sql_query % (identity, item["content"]))

            # insert into change_log (operation, description, op_timestamp, witness) values (%d, '%s', %f, %d)
            cursor.execute(self.log_insert % (2, item["res_type"]+'@'+str(target_id)+'@'+str(identity), time.time(), 0))

        for item in insert_list:
            if item["res_type"] == "cpu_info":
                cursor.execute(self.cpu_insert % (identity, item["content"]["name"], item["content"]["core"]))
                target_id = conn.insert_id()

            elif item["res_type"] == "ram_info":
                cursor.execute(self.ram_insert % (identity, item["content"]["size"], item["content"]["manufacturer"], item["content"]["sn"]))
                target_id = conn.insert_id()

            elif item["res_type"] == "disk_info":
                cursor.execute(self.disk_insert % (identity, item["content"]["size"], item["content"]["name"], item["content"]["sn"]))
                target_id = conn.insert_id()

            elif item["res_type"] == "nic_info":
                cursor.execute(self.nic_insert % (identity, item["content"]))
                target_id = conn.insert_id()

            elif item["res_type"] == "gcard_info":
                cursor.execute(self.gcard_insert % (identity, item["content"]))
                target_id = conn.insert_id()

            cursor.execute(self.log_insert % (3, item["res_type"]+'@'+str(target_id)+'@'+str(identity), time.time(), 0))

        cursor.execute("update machines set digest='%s' where id=%d" % (new_digest, identity))
        cursor.execute("update machines set update_time=%f where id=%d" % (time.time(), identity))
        conn.commit()

    def integrity_failed_log(self, identity):
        # insert into change_log (operation, description, op_timestamp, witness) values (%d, '%s', %f, %d)
        cursor = self.conn.cursor()
        cursor.execute(self.log_insert % (5, 'integrity' + '@' + str(identity) + '@' + str(identity), time.time(), 0))

    def __del__(self):
        self.conn.close()


