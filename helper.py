import os
import json
import random
import base64
import pandas
import logging
import requests
import argparse
import configparser
import urllib.parse

from bs4 import BeautifulSoup
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad


def randomString(length):
    '''
    获取随机字符串
    :param length:随机字符串长度
    '''
    ret_string = ''
    aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    for i in range(length):
        ret_string += random.choice(aes_chars)
    return ret_string


def getAesString(data, key, iv):
    '''
    用AES-CBC方式加密字符串
    :param data: 需要加密的字符串
    :param key: 密钥
    :param iv: 偏移量
    :return: base64格式的加密字符串
    '''
    # 预处理字符串
    data = str.encode(data)
    data = pad(data, AES.block_size)

    # 预处理密钥和偏移量
    key = str.encode(key)
    iv = str.encode(iv)

    # 初始化加密器
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(data)

    # 返回的是base64格式的密文
    cipher_b64 = str(base64.b64encode(cipher_text), encoding='utf-8')
    return cipher_b64


class CSULibrary(object):

    def __init__(self, userid, password):
        self.userid = userid
        self.password = password
        self.client = requests.Session()
        # seat_data = pandas.read_csv('seat.csv')
        seat_data = pandas.read_csv('seat.csv')
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.seatno = eval(config["DATABASE"]["SEAT"])
        self.area = []
        self.seatid = []
        # print(seat_data)
        # print()
        # print('valu')
        for s in self.seatno:
            self.area.append(seat_data[seat_data["NO"] == s].values[0][2])
            self.seatid.append(seat_data[seat_data["NO"] == s].values[0][0])

    def login(self):
        '''
        做任何操作前都要先登录以获得cookie
        '''
        url1 = "http://libzw.csu.edu.cn/cas/index.php"
        params1 = {
            "callback": "http://libzw.csu.edu.cn/home/web/f_second"
        }
        response1 = self.client.get(url1, params=params1)

        soup = BeautifulSoup(response1.text, 'html.parser')
        salt = soup.find('input', id="pwdEncryptSalt")['value']
        execution = soup.find('input', id="execution")['value']

        url2 = urllib.parse.unquote(response1.url)
        data2 = {
            'username': self.userid,
            'password': getAesString(randomString(64)+self.password, salt, randomString(16)),
            'captcha': '',
            '_eventId': 'submit',
            'cllt': 'userNameLogin',
            'dllt': 'generalLogin',
            'lt': '',
            'execution': execution
        }
        response2 = self.client.post(url2, data=data2)

    def reserve(self):
        '''
        预约指定位置,返回结果消息
        '''
        self.login()

        access_token = requests.utils.dict_from_cookiejar(self.client.cookies)['access_token']

        for i in range(0, len(self.seatid)):
            url = "http://libzw.csu.edu.cn/api.php/spaces/" + \
                str(self.seatid[i])+"/book"
            headers = {
                'Referer': 'http://libzw.csu.edu.cn/home/web/seat/area/1'
                # 'Referer':'http://libzw.csu.edu.cn/web/seat3?area=57&segment=1525299&day=2022-10-2&startTime=19:58&endTime=22:00'
            }
            data = {
                'access_token': access_token,
                'userid': self.userid,
                'segment': self.getBookTimeId(i)[1],
                'type': '1',
                'operateChannel': '2'
            }
            response = self.client.post(url, headers=headers, data=data)
#             print(url)
#             print(headers)
#             print(data)
#             print(response.json()['msg'] )
            if response.json()['status'] == 1:
                break
        
        logging.info(response.json()['msg'])
        if response.json()['status'] == 0:
            raise Exception(response.json()['msg'])
            os._exit(0)

    def checkIn(self):
        '''
        获取您的预约信息并签到,返回结果消息
        '''
        status = self.getCurrentUse()['statusname']
        if status != '已预约' and status != '临时离开':
            logging.info("当前座位状态不应当签到")
            os._exit(0)

        self.login()

        access_token = requests.utils.dict_from_cookiejar(self.client.cookies)[
            'access_token']
        seat_id = str(self.getCurrentUse()['id'])
        url = "http://libzw.csu.edu.cn/api.php/profile/books/"+seat_id
        headers = {
            'Referer': 'http://libzw.csu.edu.cn/home/web/seat/area/1',
        }
        data = {
            'id': seat_id,
            '_method': 'checkin',
            'access_token': access_token,
            'userid': self.userid,
            'operateChannel': '3'
        }
        response = self.client.post(url, headers=headers, data=data)
        logging.info(response.json()['msg'])
        if response.json()['status'] == 0:
            raise Exception(response.json()['msg'])

    def leave(self):
        '''
        获取您正在使用的座位信息并签到,返回结果消息
        '''
        status = self.getCurrentUse()['statusname']
        if status != '使用中':
            logging.info("当前座位状态不应当签离")
            os._exit(0)

        self.login()

        access_token = requests.utils.dict_from_cookiejar(self.client.cookies)[
            'access_token']
        seat_id = str(self.getCurrentUse()['id'])
        url = "http://libzw.csu.edu.cn/api.php/profile/books/"+seat_id
        headers = {
            'Referer': 'http://libzw.csu.edu.cn/home/web/seat/area/1',
        }
        data = {
            'id': seat_id,
            '_method': 'checkout',
            'access_token': access_token,
            'userid': self.userid,
            'operateChannel': '3'
        }
        response = self.client.post(url, headers=headers, data=data)
        logging.info(response.json()['msg'])
        if response.json()['status'] == 0:
            raise Exception(response.json()['msg'])

    def getCurrentUse(self):
        '''
        获取正在使用中的座位或研讨间,返回内容较为复杂,建议自己发包自行查看response
        '''
        url = "http://libzw.csu.edu.cn/api.php/currentuse"
        headers = {
            "Referer": "http://libzw.csu.edu.cn/home/web/seat/area/1"
        }
        params = {
            "user": self.userid
        }
        response = self.client.get(url, headers=headers, params=params)
        if len(response.json()['data']) == 0:
            logging.info("当前没有正在使用中的座位或研讨间")
            os._exit(0)
        return response.json()['data'][0]

    def getBookTimeId(self, i):
        '''
        每天每个区域都有一个独特的bookTimeId(预约时间ID)
        该函数返回今天和明天的bookTimeId
        :param i: area是一个区域数组,i指示我们获取第几位元素的bookTimeId
        '''
        url = "http://libzw.csu.edu.cn/api.php/v3areadays/"+str(self.area[i])
        headers = {
            'Referer': 'http://libzw.csu.edu.cn/home/web/seat/area/1'
        }
        response = self.client.get(url, headers=headers)
        return response.json()["data"]["list"][0]["id"], response.json()["data"]["list"][1]["id"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CSU图书馆')

    parser.add_argument('--action', type=str, help='操作类型')
    parser.add_argument('--userid', type=str, help='账号')
    parser.add_argument('--password', type=str, help='密码')
    args = parser.parse_args()
    pirnt('ok')
    LOG_FORMAT = "%(asctime)s\t%(levelname)s\t%(message)s"
    logging.basicConfig(filename='library.log',
                        level=logging.INFO, format=LOG_FORMAT)

    helper = CSULibrary(args.userid, args.password)
    # helper.reserve()
    # 故意不做异常处理，这样 Github 便会发邮件提醒
    try:
        if args.action == 'reserve':
            helper.reserve()
    except Exception:
        logging.info("预约失败")

    # elif args.action == 'checkIn':
    #     helper.checkIn()
    # elif args.action == 'leave':
    #     helper.leave()
