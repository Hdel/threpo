import os
import sqlite3
# 创建链接对象
# 打开一个到 SQLite 数据库文件 db.sqlite3 的链接
# 如果该数据库不存在则会自动创建，可以指定带有文件路径的文件名
import time

conn = sqlite3.connect('db.sqlite3')

# 获取游标对象用来操作数据库
cursor = conn.cursor()

cursor.execute('''create table agent(id, key char(32), digest char(64), op_timestamp decimal(10, 0))''')
cursor.execute("insert into agent (id, key, digest, op_timestamp) values(2, '%s', '%s', %f)" % ("a"*32, "b"*64, time.time()))
cursor.execute("select * from agent where id = 1")
value = cursor.fetchone()

conn.commit()
conn.close()
print(value)

os.unlink("db.sqlite3")
