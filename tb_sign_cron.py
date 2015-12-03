#!/home/dyh/python_virtualenv/env_Tieba_Cloud_Sign_Python/bin/python
# -*- coding: utf-8 -*-
from main2 import _browser
import sqlite3
import time
from threading import Thread
import hashlib
import json
import urllib.parse
import os

import logging
logging.basicConfig(
    level=logging.DEBUG,
    format=str('%(asctime)s [line %(lineno)d] ' +
               '<%(threadName)s> <%(levelname)s>:  %(message)s'),
    datefmt='%H:%M:%S')


DB_NAME = 'tiebacloud.sqlite3'


class _client(_browser):

    def __init__(self, bduss, tbuser_name):
        _browser.__init__(self)
        self.add_bduss2cookie(bduss)
        self.bduss = bduss
        self.get_tbs()

    def get_md5sign(self, adict):
        p_sign = ''.join([i+'={'+i+'}' for i in sorted(adict.keys())])
        p_sign += 'tiebaclient!!!'
        t_str = p_sign.format(**adict)
        t_sign = hashlib.md5(t_str.encode('utf-8')).hexdigest().upper()
        return t_sign

    def get_tbs(self, ):
        url = 'http://tieba.baidu.com/dc/common/tbs'
        with self.opener.open(url) as f:
            t_str = f.read().decode('utf-8')
        self.tbs = json.loads(t_str).get('tbs')

    def sign_single(self, tieba_id, tieba_name):
        self.add_bduss2cookie(self.bduss)
        url = 'http://c.tieba.baidu.com/c/c/forum/sign'
        postDict = {
            'fid': str(tieba_id),
            'kw': tieba_name,
            'BDUSS': self.bduss,
            'tbs': self.tbs
        }

        t_sign = self.get_md5sign(postDict)
        postDict['sign'] = t_sign

        postData = urllib.parse.urlencode(postDict)
        postData = postData.encode('utf-8')
        with self.opener.open(url, data=postData) as f:
            t_str = f.read().decode('gbk')
            data_json = json.loads(t_str)
            return data_json


def get_sign_code(codefile):
    sign_code = {}
    if os.path.exists(codefile):
        with open(codefile, 'r') as f:
            t_str = f.read()
        sign_code.update(**json.loads(t_str))
    return sign_code


def update_sign_code(sign_code, adict):
    sign_code.update(**adict)


def save_sign_code(sign_code, codefile):
    with open(codefile, 'w') as f:
        f.write(json.dumps(sign_code, ensure_ascii=False, indent=2))


def sign_cron(sign_num=20, thread_num=10):
    sign_code = get_sign_code('sign_code')
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    today = time.strftime('%Y%m%d')
    sql_cur.execute('''select
                    user_tbuser.bduss,
                    tieba_list.tbuser_name,
                    tieba_list.tb_name,
                    tieba_list.tb_id
                    from user_tbuser
                    inner join tieba_list
                    on user_tbuser.tbuser_name=
                    tieba_list.tbuser_name
                    where user_tbuser.bduss_ok=1
                    and tieba_list.signed=0
                    limit ?
                    ''', (sign_num, ))
    to_signs = sql_cur.fetchall()
    if not to_signs:
        logging.debug('no tieba need to sign')
        return
    sign_info = []
    client_dic = {}

    def subthread(to_signs, client_dic, sign_info, sign_date, sign_code):
        while to_signs:
            bduss, tbuser_name, tb_name, tb_id = to_signs.pop(0)
            if tbuser_name not in client_dic:
                client_dic[tbuser_name] = _client(bduss, tbuser_name)

            response = client_dic[tbuser_name].sign_single(tb_id, tb_name)
            err_no = response.get('error_code')
            err_msg = response.get('error_msg')
            update_sign_code(sign_code, {err_no: err_msg})
            sign_info.append((tbuser_name, tb_name, sign_date, err_no))

    ps = [Thread(target=subthread,
                 args=(to_signs, client_dic, sign_info, today, sign_code))
          for i in range(thread_num)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()

    save_sign_code(sign_code, 'sign_code')

    sql_cn.executemany('''insert into sign_records
                        (tbuser_name, tb_name, sign_date, err_no)
                        values (?,?,?,?)
                        ''', sign_info)
    sql_cn.executemany('''update tieba_list
                       set signed=1
                       where tbuser_name=?
                       and tb_name=?
                       ''', [i[:2] for i in sign_info])
    sql_cn.commit()

if __name__ == '__main__':
    sign_cron()
