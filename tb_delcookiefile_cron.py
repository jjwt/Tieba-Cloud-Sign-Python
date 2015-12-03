#!/home/dyh/python_virtualenv/env_Tieba_Cloud_Sign_Python/bin/python
# -*- coding: utf-8 -*-

import sqlite3
import time
import os
from glob import glob


DB_NAME = 'tiebacloud.sqlite3'


def del_cookiefile():
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select filename
                    from todo_delcookiefile
                    where expire_time < %d
                    and deleted=0''' % int(time.time()))
    filenames = sql_cur.fetchall()
    if filenames:
        cur_dir = os.path.abspath(os.path.dirname(__file__))
        for f in filenames:
            os.remove(os.path.join(cur_dir, f[0]))
        pass


def del_cookiefile2():
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    os.chdir(cur_dir)
    filenames_todel = glob('temp_cookie_*')
    if not filenames_todel:
        return None
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('select tbuser_name from user_tbuser')
    filenames = ['temp_cookie_'+i[0] for i in sql_cur.fetchall()]
    filenames_todel = [i for i in filenames_todel if i not in filenames]
    for f in filenames_todel:
        os.remove(f)
    pass

if __name__ == '__main__':
    del_cookiefile()
