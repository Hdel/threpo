from configparser import ConfigParser
import pymysql
import os


def get_database_connection():
    config = ConfigParser()

    config.read(os.path.dirname(__file__) + "/config.conf")
    host = config.get("mysql", "host")
    port = config.get("mysql", "port")
    database = config.get("mysql", "database")
    username = config.get("mysql", "username")
    password = config.get("mysql", "password")
    conn = pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)

    return conn


def database_init():
    print("Establishing database connection...")
    conn = get_database_connection()
    cursor = conn.cursor()
    create_table_list = [admin_log, change_log, config_info, cpu_info, disk_info,
                         gcard_info, machines, nic_info, ram_info, staff_info, switch_table]

    print("Creating tables...", end="")
    for sql_create in create_table_list:
        cursor.execute(sql_create)

    conn.commit()
    print("Done")
    conn.close()


def database_insert(conn: pymysql.Connection, items):
    cursor = conn.cursor()
    for item in items:
        table_name = item
        for entry in items[item]:
            fields_fragment = ""
            values_fragment = ""
            for field in entry:
                fields_fragment += str(field) + " "
                values_fragment += str(entry[field]) + " "

            cursor.execute("insert into %s (%s) values(%s)" % (table_name, fields_fragment, values_fragment))

    conn.commit()


admin_log = """CREATE TABLE IF NOT EXISTS `sigma_log` (
                             `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                             `admin_id` bigint(20) unsigned DEFAULT NULL,
                             `operation` smallint(6) DEFAULT NULL,
                             `description` varchar(100) DEFAULT NULL,
                             `op_timestamp` decimal(10,0) DEFAULT NULL,
                             `state` smallint(6) DEFAULT NULL,
                             PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

change_log = """CREATE TABLE IF NOT EXISTS `change_log` (
                              `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                              `operation` smallint(5) unsigned DEFAULT NULL,
                              `description` varchar(200) DEFAULT NULL,
                              `op_timestamp` decimal(10,0) DEFAULT NULL,
                              `witness` int(10) DEFAULT NULL,
                              `comment` varchar(100) DEFAULT NULL,
                              `machine` int(11) DEFAULT NULL,
                              `lock_time` decimal(10,0) DEFAULT '0',
                              PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

config_info = """CREATE TABLE IF NOT EXISTS `config_info` (
                               `conf` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
                               `conf_section` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
                               `conf_value` int(5) DEFAULT NULL,
                               PRIMARY KEY (`conf`)) ENGINE=InnoDB DEFAULT CHARSET=utf8"""

cpu_info = """CREATE TABLE IF NOT EXISTS `cpu_info` (
                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                            `machine` bigint(11) DEFAULT NULL,
                            `caption` varchar(100) DEFAULT NULL,
                            `core` smallint(6) DEFAULT NULL,
                            PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

disk_info = """CREATE TABLE IF NOT EXISTS `disk_info` (
                             `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                             `machine` bigint(20) DEFAULT NULL,
                             `caption` varchar(100) DEFAULT NULL,
                             `size` int(10) unsigned DEFAULT NULL,
                             `sn` varchar(64) DEFAULT NULL,
                             PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

gcard_info = """CREATE TABLE IF NOT EXISTS `gcard_info` (
                              `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                              `machine` bigint(20) DEFAULT NULL,
                              `caption` varchar(100) DEFAULT NULL,
                              PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

machines = """CREATE TABLE IF NOT EXISTS `machines` (
                            `id` bigint(11) unsigned NOT NULL AUTO_INCREMENT,
                            `secret` char(32) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
                            `digest` char(64) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
                            `state` smallint(6) DEFAULT NULL,
                            `update_time` decimal(10,0) DEFAULT NULL,
                            `comment` varchar(40) DEFAULT NULL,
                            PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

nic_info = """CREATE TABLE IF NOT EXISTS `nic_info` (
                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                            `machine` bigint(20) DEFAULT NULL,
                            `mac` char(17) DEFAULT NULL,
                            PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

ram_info = """CREATE TABLE IF NOT EXISTS `ram_info` (
                            `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                            `machine` bigint(20) DEFAULT NULL,
                            `size` int(10) unsigned DEFAULT NULL,
                            `manufacturer` varchar(100) DEFAULT NULL,
                            `sn` varchar(64) DEFAULT NULL,
                            PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

staff_info = """CREATE TABLE IF NOT EXISTS `staff_info` (
                              `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                              `email` varchar(40) DEFAULT NULL,
                              `digest` char(64) DEFAULT NULL,
                              `role` tinyint(4) DEFAULT '1',
                              PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""

switch_table = """CREATE TABLE IF NOT EXISTS `switch_table` (
                                `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                                `ip_addr` char(15) DEFAULT NULL,
                                `op_timestamp` decimal(10,0) DEFAULT NULL,
                                `username` varchar(20) DEFAULT NULL,
                                `password` varchar(30) DEFAULT NULL,
                                `switch_name` varchar(10) CHARACTER SET utf8 COLLATE utf8_general_ci DEFAULT NULL,
                                `switch_type` varchar(30) DEFAULT NULL,
                                PRIMARY KEY (`id`)) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8"""