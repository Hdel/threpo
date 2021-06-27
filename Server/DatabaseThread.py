import os
import smtplib
import time
from configparser import ConfigParser
import threading
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


import DatabaseUtils


class DatabaseThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        config = ConfigParser()
        config.read(os.path.dirname(__file__) + "/config.conf")
        check_interval = int(config.get("interval", "check_exist"))

        conn = DatabaseUtils.get_database_connection()

        while True:
            print("start...")
            cursor = conn.cursor()
            cursor.execute("select id from machines where (state = 0 or state = 1) and %f-update_time > %d"
                           % (time.time(), check_interval))
            obj_list = cursor.fetchall()
            cursor.execute("select id from switch_table where %f-op_timestamp > %d" % (time.time(), 240))
            switch_timeout_list = cursor.fetchall()

            log_insert = "insert into change_log (operation, description, op_timestamp, witness, machine) values (%d, '%s', " \
                         "%f, %d, %d) "
            for item in obj_list:
                cursor.execute("select * from change_log where operation=4 and machine=%d and witness=0" % (item[0]))
                cursor.execute(log_insert % (4,'machines'+'@'+str(item[0])+'@'+str(item[0]), time.time(), 0, item[0]))
            for item in switch_timeout_list:
                cursor.execute(log_insert % (11, 'switch'+str(item[0]), time.time(), 0, item[0]))

            cursor.execute("update change_log set witness=0 where witness=-1 and %f-op_timestamp > %d"
                           % (time.time(), 300))

            config = ConfigParser()
            config.read(os.path.dirname(__file__) + "/config.conf")

            alert_items = config.items("alert")
            email_list = ""
            if alert_items[0][1] == "1":
                cursor.execute("select * from admin_log where status=0 and operation=0")
                result_list = cursor.fetchall()
                for result in result_list:
                    if result[3].split("@")[1] == "1":
                        email_list += "A change has been marked abnormal by a staff, please check it\r\n"
            if alert_items[1][1] == "1":
                cursor.execute("select * from admin_log where status=0 and operation=1")
                if cursor.fetchone() is not None:
                    email_list += "Config has been changed by a staff, please check it\r\n"
            if alert_items[2][1] == "1":
                cursor.execute("select * from change_log where %f - op_timestamp > 120 and (operation = 4 or operation = 2 or operation = 11)"
                               % (time.time()))
                if cursor.fetchone() is not None:
                    email_list += "A timeout event happened in the system, please check it.\r\n"

            cursor.execute("select email from staff_info")
            addr_list = cursor.fetchall()

            # for addr in addr_list:
            #     send_reg_email(addr[0], email_list)

            conn.commit()
            time.sleep(check_interval)

        conn.close()


def send_reg_email(email, password):
    print("send...")
    mail_host = "smtp.sina.cn"
    mail_user = "******"
    mail_pass = "******"

    sender = '******'
    receivers = [email]

    message = MIMEMultipart()
    message['From'] = Header(mail_user)
    message['To'] = Header(email, 'utf-8')

    subject = '错误报告'
    message['Subject'] = Header(subject, 'utf-8')

    content1 = MIMEText(password, 'plain', 'utf-8')
    message.attach(content1)
    try:
        smtpObj = smtplib.SMTP_SSL(mail_host)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print("sent done")
    except:
        print("something wrong...")
    finally:
        smtpObj.close()