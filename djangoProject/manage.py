#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoProject.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

# 连接地址：pc-bp18rn0tqu85a1600-public.rwlb.rds.aliyuncs.com
# 端口：3306
# 数据库名称：polardb_mysql_13045ydo
# 账号：lab_1919287857
# 密码：8068d4c15259_#@Aa

if __name__ == '__main__':
    main()
