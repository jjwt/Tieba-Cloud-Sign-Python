#!/home/dyh/python_virtualenv/env_Tieba_Cloud_Sign_Python/bin/python
# -*- coding: utf-8 -*-
import sqlite3
from main import _browser

DB_NAME = 'tiebacloud.sqlite3'


def update_tieba_list():
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('delete from tieba_list')
    sql_cn.commit()
    sql_cur.execute('''select tbuser_name, bduss
                    from user_tbuser
                    where bduss_ok=1''')
    result = sql_cur.fetchall()
    if not result:
        print('can not find avaliable bduss')
        return
    tblist = []
    for tbuser_name, bduss in result:
        b = _browser(cookiefile='temp_cookie_'+tbuser_name)
        tblist += [(tbuser_name, i[1], i[0]) for i in b.get_tblist(bduss)]

    sql_cn.executemany('''insert into tieba_list
                       (tbuser_name, tb_name, tb_id)
                       values (?,?,?)
                       ''', tblist)
    sql_cn.commit()


if __name__ == '__main__':
    update_tieba_list()
