#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, render_template
from flask import make_response, redirect, url_for, jsonify
import sqlite3
from base64 import b64encode
from os import urandom
from hashlib import sha256
from functools import wraps
import time
import re
from math import ceil
from os.path import exists
import http.cookiejar
import http.cookies
import urllib.parse
import urllib.request
from random import choice
from threading import Thread


import logging
logging.basicConfig(
    level=logging.DEBUG,
    format=str('%(asctime)s [line %(lineno)d] ' +
               '<%(threadName)s> <%(levelname)s>:  %(message)s'),
    datefmt='%H:%M:%S')

app = Flask(__name__)


# SQLITE3 数据库名称(存放百度贴吧云签到的)
DB_NAME = 'tiebacloud.sqlite3'
NUM_PER_TBLIST = 15
NUM_PER_TBUSERS = 15
NUM_PER_SIGNRECORDS = 15


DB_ADMIN = 'jjwt'
DB_PASSWD = 'jjwt'

ERR_MSG = {
    '0': '操作成功!',
    '1': '用户名或密码为空!',
    '2': '用户名已经存在',
    '3': '用户名或密码错误!',
    '4': '用户名或密码格式错误!',
    '5': '操作失败,未知错误!',
    '6': '您无权进行此操作',
    '7': '该用户并不存在',
    '8': '提交参数错误',
    '9': '其他用户已绑定该贴吧用户',
    '10': '该用户bduss已经失效，请重新绑定',
    '11': '获取贴吧列表失败',
    '12': '数据库操作失败，未知错误',
    '13': '登录错误操作次数已达过多，请稍后再试',
    '14': '该用户已被封禁，请与网站管理员联系',
    '15': '已添加到系统任务列表，请稍后查看',
    '16': '已添加到系统任务列表，请勿重复提交',
}

# utils


class _browser(object):

    def __init__(self, **kwargs):
        self.cookiefile = kwargs.get('cookiefile')
        if self.cookiefile:
            self.cj = http.cookiejar.MozillaCookieJar(self.cookiefile)
            if exists(self.cookiefile):
                self.cj.load()
        else:
            logging.debug("cookiefile does not exists")
            self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))
        if kwargs.get('isPhone', True):
            self.opener.headers = {
                'User-agent': 'Phone'+str(choice(range(1, 256)))
            }
        else:
            self.opener.addheaders = [
                ('User-agent',
                 'Mozilla/5.0 (X11; Linux x86_64; rv:39.0)' +
                 ' Gecko/20100101 Firefox/39.0')]
        pass

    def get_ck(self, k):
        '''
        get_ck(self, k) -> str
        k -> key
        get value of key in cookies
        '''
        for c in self.cj:
            if c.name == k:
                return c.value
        return None

    def get_vcodestr(self, username):
        url = 'http://wappass.baidu.com/passport/'
        postDict = {
            "login_username": username,
            "login_loginpass": username
            }
        postData = urllib.parse.urlencode(postDict)
        postData = postData.encode('utf-8')
        with self.opener.open(url, data=postData) as f:
            t_str = f.read().decode('utf-8')

        p_vcodestr = '''\s
                src="http://wappass\.baidu\.com/cgi-bin/genimage\?
                (?P<vcodestr>[^"]+)"'''
        search_result = re.search(p_vcodestr, t_str, flags=(re.M | re.VERBOSE))
        if search_result:
            if self.cookiefile:
                self.cj.save()
                sql_add_cookiefile(self.cookiefile)
            return search_result.group('vcodestr')
        else:
            logging.debug("can not find vcodestr")
            return None

    def get_bduss(self, username, password, verifycode, vcodestr):
        url = 'http://wappass.baidu.com/passport/?verifycode='+verifycode
        postDict = {
            'username': username,
            'password': password,
            'verifycode': verifycode,
            'login_save': '3',
            'vcodestr': vcodestr,
            'aaa': '登录',
            'login': 'yes',
            'can_input': '0',
            'u': 'http://m.baidu.com/?action=login',
            'tn': '',
            'tpl': '',
            'ssid': '000000',
            'form': '0',
            'bd_page_type': '1',
            'uid': 'wiaui_1316933575_9548',
            'isPhone': 'isPhone'
            }
        postData = urllib.parse.urlencode(postDict)
        postData = postData.encode('utf-8')
        with self.opener.open(url, data=postData) as f:
            t_str = f.read().decode('utf-8')
        e = self.get_ck('BDUSS')
        if not e:
            logging.debug('can not get bduss, the response is')
            logging.debug(t_str)
        return e

    def add_bduss2cookie(self, bduss):
        '''add bduss info into cookie,
        if exists, change it to given bduss
        '''
        c = http.cookiejar.Cookie(version=0,
                                  name='BDUSS',
                                  value=bduss,
                                  port=None, port_specified=None,
                                  domain='.baidu.com',
                                  domain_specified=None,
                                  domain_initial_dot=None,
                                  path='/',
                                  path_specified=None,
                                  secure=None,
                                  expires=time.time()+2592000,
                                  discard=None,
                                  comment=None,
                                  comment_url=None,
                                  rest=None,
                                  rfc2109=False,
                                  )
        self.cj.set_cookie(c)

    def get_tblist(self, bduss, thread_num=8):
        '''
        get tieba list of tieba user with bduss given
        '''
        self.add_bduss2cookie(bduss)
        url = 'http://tieba.baidu.com/f/like/mylike?&pn=%d'
        with self.opener.open(url % 1) as f:
            t_str = f.read()
            t_str = t_str.decode('gbk', errors='ignore')
        p_url = '<a href=\"/f/like/mylike\?&pn=(?P<num>\d+)\">尾页</a>'
        result = re.search(p_url, t_str)
        if result:
            max_page = int(result.group('num'))
        else:
            max_page = 1

        thread_num = min(max_page, thread_num)
        likes_dict = {'cur': 1, 'max': max_page+1, 'tb_list': []}

        def subthread(aobj, adict, p_url, thread_name):
            p_kw = 'balvid=\"(\d+)\" balvname="([^\"]+)\"'
            while adict['cur'] < adict['max']:
                t_n = adict['cur']
                adict['cur'] += 1
                with aobj.opener.open(p_url % t_n) as f:
                    t_str = f.read().decode('gbk')
                adict['tb_list'] += re.findall(p_kw, t_str)
                print('subthread %d get likes at page %d' % (thread_name, t_n))

        ps = [Thread(target=subthread, args=(self, likes_dict, url, i))
              for i in range(thread_num)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        if self.cookiefile:
            self.cj.save()

        return [(i[0], urllib.parse.unquote(i[1], encoding='gbk'))
                for i in likes_dict['tb_list']]


def add_token(username):
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select user_id from user
               where username=?''', (username,))
    user_id = sql_cur.fetchone()[0]
    token = gen_token()
    expire_time = int(time.time())+2592000
    sql_cur.execute('''insert into persis_token
                    (user_id,token,expire_time) values (?,?,?)''',
                    (user_id, token, expire_time))
    sql_cn.commit()
    resp = make_response(redirect(url_for('page_main')))
    token = str(user_id)+'s'+token
    resp.set_cookie('token', token, expires=expire_time)
    return resp


def json_err(err_no, **kwargs):
    data_dict = {
        'err_no': err_no,
        'err_msg': ERR_MSG[err_no]
    }
    data_dict.update(**kwargs)
    return jsonify(**data_dict)


def sql_add_user(username, password, role=1, banned=0):
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select 1 from user
               where username=?''', (username,))
    result = sql_cur.fetchone()
    if result:
        return '2'
    try:
        salt = gen_salt()
        pwd_hash = gen_pwd_hash(password, salt)
        sql_cn.execute('''insert into user
                    (username,pwd_hash,role,salt,banned)
                    values (?,?,?,?,?)
                       ''', (username, pwd_hash, role, salt, banned))
        sql_cn.commit()
        return '0'
    except:
        return '5'


def sql_add_cookiefile(filename):
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select expire_time
                    from todo_delcookiefile
                    where filename=?
                    and deleted=0
                    ''', (filename, ))
    result = sql_cur.fetchone()
    expire_time = int(time.time()) + 900
    if result:
        if int(result[0]) > expire_time:
            return
    sql_cur.execute('''insert into todo_delcookiefile
                    (filename,expire_time)
                    values (?,?)
                    ''', (filename, expire_time))
    sql_cn.commit()


def sql_get_tblist(pn, tbuser_name):
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select count(1) from tieba_list
                    where tbuser_name=?''', (tbuser_name,))
    count_tblist = int(sql_cur.fetchone()[0])
    max_pn_tblist = ceil(count_tblist / NUM_PER_TBLIST)
    if max_pn_tblist == 0:
        tblist = []
    else:
        sql_cur.execute('''select tb_name, tb_id, signed from tieba_list
                        where tbuser_name=?
                        limit %d offset ?''' % NUM_PER_TBLIST,
                        (tbuser_name, (int(pn)-1)*NUM_PER_TBLIST))
        tblist = sql_cur.fetchall()
    data_dict = {
        'max_pn_tblist': max_pn_tblist,
        'tblist': tblist,
        'pn_tblist': int(pn),
        'count_tblist': count_tblist,
        'num_per_tblist': NUM_PER_TBLIST,
    }
    return data_dict


def sql_get_signrecords(pn, tbuser_name):
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select count(1) from sign_records
                    where tbuser_name=?''', (tbuser_name,))
    count_signrecords = int(sql_cur.fetchone()[0])
    max_pn_signrecords = ceil(count_signrecords / NUM_PER_SIGNRECORDS)
    if max_pn_signrecords == 0:
        signrecords = []
    else:
        sql_cur.execute('''select tb_name,
                        sign_date, err_no
                        from sign_records
                        where tbuser_name=?
                        limit %d offset ?''' % NUM_PER_SIGNRECORDS,
                        (tbuser_name, (int(pn)-1)*NUM_PER_SIGNRECORDS))
        signrecords = sql_cur.fetchall()
    data_dict = {
        'max_pn_signrecords': max_pn_signrecords,
        'signrecords': signrecords,
        'pn_signrecords': int(pn),
        'count_signrecords': count_signrecords,
        'num_per_signrecords': NUM_PER_SIGNRECORDS,
    }
    return data_dict


def reg_check_username(username):
    if not 4 <= len(username) <= 8:
        logging.debug('username length error!')
        return False
    if re.search('\s', username):
        logging.debug('username has blank char!')
        return False
    return True


def reg_check_password(password):
    if not 6 <= len(password) <= 16:
        logging.debug('password length error!')
        return False
    has_chr = False
    has_digit = False
    for i in password:
        if re.match('[a-zA-Z]', i):
            has_chr = True
        elif i.isdigit():
            has_digit = True
        else:
            logging.debug('password has unavalieable char!')
            return False
    if has_chr and has_digit:
        return True
    logging.debug('password does not have both char and digits!')
    logging.debug('has_chr,has_digit:%s %s' % (has_chr, has_digit))
    return False


def gen_salt():
    return b64encode(urandom(64)).decode('utf-8')


def gen_pwd_hash(pwd, salt):
    return sha256((salt+pwd).encode('utf-8')).hexdigest()


def gen_token():
    token = b64encode(urandom(128)).decode('utf-8')
    return token


def check_login_err_count():
    ip = request.remote_addr
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select expire_time
                    from login_err
                    where ip=?
                    and err_count=3
                    and deleted=0
                    ''', (ip,))
    result = sql_cur.fetchone()
    if result:
        expire_time = int(result[0])
        if time.time() > expire_time:
            sql_cur.execute('''update login_err
                            set deleted=1
                            where ip=?
                            ''', (ip,))
            sql_cn.commit()
            return True

        return False

    return True


def add_login_err():
    ip = request.remote_addr
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select err_count
                    from login_err
                    where ip=?
                    and deleted=0
                    ''', (ip,))
    result = sql_cur.fetchone()
    if result:
        err_count = int(result[0]+1)
        sql_cur.execute('''update login_err
                        set err_count=?
                        where ip=?
                        ''', (err_count, ip))
        sql_cn.commit()
    else:
        expire_time = int(time.time())+900
        sql_cur.execute('''insert into login_err
                        (ip,err_count,expire_time)
                        values (?,1,?)
                        ''', (ip, expire_time))
        sql_cn.commit()
    pass


# init database
def init_database():
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    with open('init_tables.sql', 'r', encoding='utf-8') as f:
        t_str = f.read()
    sql_cur.executescript(t_str)
    sql_cn.commit()
    salt = gen_salt()
    pwd_hash = gen_pwd_hash(DB_PASSWD, salt)
    sql_cn.execute('''insert or ignore into user
                (username,pwd_hash,salt,role)
                values (?,?,?,0)
                ''', (DB_ADMIN, pwd_hash, salt))
    sql_cn.commit()

# decorators


def de_check_token(func):
    '''
    1. check if has token in cookies
        if not -> redirect to login page
    2. check if match pattern(user_id,'s',token)
        if not -> redirect to login page, remove token
    3. check if token in database
        if not -> redirect to login page, remove token
    4. check if expired
        if yes -> redirect to login page, remove token
    5. check if banned
        if yes -> redirect to banned page
    6. transform user_id, username, role info of user
        to the func
    '''
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('page_login'))
        t = token.split('s', 1)
        if not (len(t) == 2 and t[0].isdigit()):
            resp = make_response(redirect(url_for('page_login')))
            resp.set_cookie('token', expires=0)
            return resp
        user_id, ptoken = t
        sql_cn = sqlite3.connect(DB_NAME)
        sql_cur = sql_cn.cursor()
        sql_cur.execute('''select expire_time
                        from persis_token
                        where user_id=?
                        and token=?
                        and deleted=0
                        ''', (user_id, ptoken))
        result = sql_cur.fetchone()
        if not result:
            resp = make_response(redirect(url_for('page_login')))
            resp.set_cookie('token', expires=0)
            return resp
        if time.time() > int(result[0]):
            sql_cur.execute('''update persis_token
                            set deleted=1
                            where user_id=?
                            and token=?
                            ''', (user_id, ptoken))
            sql_cn.commit()
            resp = make_response(redirect(url_for('page_login')))
            resp.set_cookie('token', expires=0)
            return resp
        sql_cur.execute('''select username,role,banned
                        from user
                        where user_id=?
                        ''', (user_id, ))
        username, role, banned = sql_cur.fetchone()
        if int(banned) == 1:
            return redirect(url_for('page_banned'))
        data_dict = {
            'user_id': user_id,
            'username': username,
            'role': role,
        }
        kwargs.update(**data_dict)
        result = func(*args, **kwargs)
        return result
    return wrapper


def de_check_tbuid(func):
    '''
    1. check if has tbuser_id in request
        if not -> return error
    2. check if (user,tbuser) couple in database
        if not -> return error
    3. transform tbuser_id,tbuser_name,bduss,bduss_ok info of user
        to the func
    '''
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = kwargs.get('user_id')
        tbuser_id = request.form.get('tbuid')
        if not tbuser_id:
            logging.debug('can not find tbuser_id')
            return json_err('8')
        sql_cn = sqlite3.connect(DB_NAME)
        sql_cur = sql_cn.cursor()
        sql_cur.execute('''select tbuser_name,bduss,bduss_ok
                        from user_tbuser
                        where id=?
                        and user_id=?
                        ''', (tbuser_id, user_id))
        result = sql_cur.fetchone()
        if not result:
            logging.debug('can not find tbuser_id in sql')
            return json_err('8')
        tbuser_name, bduss, bduss_ok = result
        data_dict = {
            'tbuser_name': tbuser_name,
            'tbuser_id': tbuser_id,
            'bduss': bduss,
            'bduss_ok': bduss_ok,
        }
        kwargs.update(**data_dict)
        result = func(*args, **kwargs)
        return result
    return wrapper


# all route


@app.route('/banned')
def page_banned():
    return ERR_MSG['14']


@app.route('/register', methods=['GET', 'POST'])
def page_register(**kwargs):
    if request.method == 'GET':
        return render_template('register.html')
    username = request.form.get('username')
    password = request.form.get('password')
    passwordag = request.form.get('passwordag')

    if not (reg_check_username(username) and reg_check_password(password)):
        data_dict = {
            'err': ERR_MSG['4'],
            'username': username,
            'password': password,
            'passwordag': passwordag,
        }
        return render_template('register.html', **data_dict)
    e = sql_add_user(username, password)
    if e == '0':
        return add_token(username)
    if e not in ['1', '2', '5']:
        e = '5'

    data_dict = {
        'err': ERR_MSG[e],
        'username': username,
        'password': password,
        'passwordag': passwordag,
    }
    return render_template('register.html', **data_dict)


@app.route('/login', methods=['GET', 'POST'])
def page_login():
    if request.method == 'GET':
        return render_template('login.html')

    if not check_login_err_count():
        return render_template('login.html', err=ERR_MSG['13'])

    username = request.form.get('username')
    password = request.form.get('password')
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select pwd_hash,salt,role,banned
                from user where username=?
                ''', (username,))
    result = sql_cur.fetchone()
    if not result:
        data_dict = {
            'err': ERR_MSG['3'],
            'username': username,
            'password': password,
        }
        add_login_err()
        return render_template('login.html', **data_dict)
    pwd_hash, salt, role, banned = result
    if gen_pwd_hash(password, salt) != pwd_hash:
        data_dict = {
            'err': ERR_MSG['3'],
            'username': username,
            'password': password,
        }
        add_login_err()
        return render_template('login.html', **data_dict)
    if int(banned) == 1:
        return redirect(url_for('page_banned'))
    return add_token(username)


@app.route('/logout')
def page_logout():
    token = request.cookies.get('token')
    if token:
        t = token.split('s', 1)
        if (len(t) == 2 and t[0].isdigit()):
            user_id, ptoken = t
            sql_cn = sqlite3.connect(DB_NAME)
            sql_cur = sql_cn.cursor()
            sql_cur.execute('''update persis_token
                            set deleted=1
                            where user_id=?
                            and token=?
                            ''', (user_id, ptoken))
            sql_cn.commit()

    resp = make_response(redirect(url_for('page_login')))
    resp.set_cookie('token', expires=0)
    return resp


@app.route('/')
@de_check_token
def page_main(**kwargs):
    role = kwargs.get('role')
    if int(role) == 1:
        return page_user_com(**kwargs)

    if int(role) == 0:
        return page_user_admin(**kwargs)


def page_user_com(tmpfile='user_common.html', **kwargs):
    user_id = kwargs.get('user_id')
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select count(1)
                    from user_tbuser
                    where user_id=?
                    ''', (user_id,))
    count_tbusers = int(sql_cur.fetchone()[0])
    max_pn_tbusers = ceil(count_tbusers / NUM_PER_TBUSERS)
    pn = kwargs.get("pn", 1)
    if max_pn_tbusers == 0:
        tbusers = []
    else:
        sql_cur.execute('''select id,tbuser_name,bduss,bduss_ok
                        from user_tbuser
                        where user_id=?
                        limit %d offset ?''' % NUM_PER_TBUSERS,
                        (user_id, (int(pn)-1)*NUM_PER_TBUSERS))
        tbusers = sql_cur.fetchall()
    data_dict = {'tbusers': tbusers}
    data_dict = {
        'max_pn_tbusers': max_pn_tbusers,
        'tbusers': tbusers,
        'pn_tbusers': int(pn),
        'count_tbusers': count_tbusers,
        'num_per_tbusers': NUM_PER_TBUSERS,
    }
    data_dict.update(**kwargs)
    return render_template(tmpfile, **data_dict)


def page_user_admin(**kwargs):
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select user_id,username,role,banned from user''')
    users = sql_cur.fetchall()
    data_dict = {'users': users}
    data_dict.update(**kwargs)
    return render_template('user_admin.html', **data_dict)


@app.route('/getvercode', methods=['GET', 'POST'])
@de_check_token
def ajax_get_vcode(**kwargs):
    tbuser_name = request.form.get('tbuser_name')
    if not tbuser_name:
        return json_err('1')
    b = _browser(cookiefile='temp_cookie_'+tbuser_name)
    vcodestr = b.get_vcodestr(tbuser_name)
    if vcodestr:
        logging.debug('find vcodestr:'+vcodestr)
        return json_err('0', vcodestr=vcodestr)
    else:
        return json_err('5')


# @app.route('/updatetblist')
@de_check_tbuid
@de_check_token
def ajax_update_tblist(**kwargs):
    user_id = kwargs.get('user_id')
    tbuser_name = kwargs.get('tbuser_name')
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select done,bduss_ok
                    from todo_updatetblist
                    where user_id=?
                    and tbuser_name=?
                    ''', (user_id, tbuser_name))
    result = sql_cur.fetchone()
    if result:
        done, bduss_ok = result
        if int(bduss_ok) == 0:
            return json_err('10')
        if int(done) == 0:
            return json_err('16')
    else:
        sql_cur.execute('''insert into todo_updatetblist
                        (user_id,tbuser_name)
                        values (?,?)''', (user_id, tbuser_name))
        sql_cn.commit()
        return json_err('15')


@app.route('/tbuser', methods=['GET', 'POST'])
@de_check_token
@de_check_tbuid
def ajax_tbuser(**kwargs):
    '''
    output -> 1. 1st page of tblist, max_page_tblist
              2. 1st page of sign_records, max_page_signrecords
    '''
    tbuser_name = kwargs.get('tbuser_name')
    data_dict = {}
    data_dict.update(**kwargs)
    data_dict.update(**sql_get_tblist(1, tbuser_name))
    data_dict.update(**sql_get_signrecords(1, tbuser_name))
    return render_template('tbuser.html', **data_dict)


@app.route('/tblist', methods=['GET', 'POST'])
@de_check_token
@de_check_tbuid
def ajax_tblist(**kwargs):
    tbuser_name = kwargs.get('tbuser_name')
    pn = request.form.get('pn', 1)
    if not str(pn).isdigit():
        return json_err('8')
    data_dict = {}
    data_dict.update(**kwargs)
    data_dict.update(**sql_get_tblist(pn, tbuser_name))
    return render_template('tblist.html', **data_dict)


@app.route('/signrecords', methods=['GET', 'POST'])
@de_check_token
@de_check_tbuid
def ajax_signrecords(**kwargs):
    tbuser_name = kwargs.get('tbuser_name')
    pn = request.form.get('pn', 1)
    if not str(pn).isdigit():
        return json_err('8')
    data_dict = {}
    data_dict.update(**kwargs)
    data_dict.update(**sql_get_signrecords(pn, tbuser_name))
    return render_template('signrecords.html', **data_dict)


@app.route('/firstpage')
@de_check_token
def ajax_firstpage(**kwargs):
    return page_user_com(tmpfile='firstpage.html', **kwargs)


@app.route('/addtbuser', methods=['GET', 'POST'])
@de_check_token
def ajax_add_tbuser(**kwargs):
    if request.method == 'GET':
        return render_template('addtbuser.html')
    tbuser_name = request.form.get('tbuser_name')
    tbuser_pw = request.form.get('tbuser_pw')
    verifycode = request.form.get('verifycode')
    vcodestr = request.form.get('vcodestr')
    if not all((tbuser_name, tbuser_pw, verifycode, vcodestr),):
        return json_err('8')

    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    sql_cur.execute('''select tbuser_name from user_tbuser
                    where tbuser_name=?
                    ''', (tbuser_name,))
    result = sql_cur.fetchone()
    if result:
        return json_err('2')
    b = _browser(cookiefile='temp_cookie_'+tbuser_name)
    bduss = b.get_bduss(tbuser_name, tbuser_pw, verifycode, vcodestr)
    if not bduss:
        return json_err('5')
    try:
        user_id = kwargs.get('user_id')
        sql_cur.execute('''insert into user_tbuser
                        (user_id,tbuser_name,bduss,bduss_ok)
                        values (?,?,?,1)
                        ''', (user_id, tbuser_name, bduss))
        sql_cn.commit()
        sql_cur.execute('''select id from user_tbuser
                        where tbuser_name=?
                        ''', (tbuser_name,))
        tbuser_id = sql_cur.fetchone()[0]
        return json_err('0', tbuser_id=tbuser_id, tbuser_name=tbuser_name)
    except:
        return json_err('5')


@app.route('/deltbuser', methods=['GET', 'POST'])
@de_check_token
@de_check_tbuid
def ajax_del_tbuser(**kwargs):
    tbuser_id = kwargs.get('tbuser_id')
    tbuser_name = kwargs.get('tbuser_name')
    user_id = kwargs.get('user_id')
    sql_cn = sqlite3.connect(DB_NAME)
    sql_cur = sql_cn.cursor()
    try:
        sql_cur.execute('''delete from user_tbuser
                            where id=?
                            and user_id=?
                            ''', (tbuser_id, user_id))
        sql_cur.execute('''delete from tieba_list
                        where tbuser_name=?
                        ''', (tbuser_name,))
        sql_cur.execute('''delete from sign_records
                        where tbuser_name=?
                        ''', (tbuser_name,))
        sql_cn.commit()
        return json_err('0')
    except:
        return json_err('12')


if __name__ == '__main__':
    # app.run()
    init_database()
    app.run(host='0.0.0.0', port=9527, debug=True)
