#!/usr/bin/python3
import http.client as httplib
import argparse
import os
import json
from pprint import pprint
from rocketchat_API.rocketchat import RocketChat
from urllib3.exceptions import InsecureRequestWarning
import requests
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



class RequestServer():
    def __init__(self, host, user, password, id_user, id_session, session):
        print("Init class request server")
        self.HOST = host
        self.user = user
        self.id_session = id_session
        self.id_user = id_user
        self.password = password
        self.rocket = None
        self.session = session

    def login(self):
        self.rocket = RocketChat(self.user, self.password, self.id_session, self.id_user, server_url=self.HOST,
                                 session=self.session)
        return self.rocket.me().json()

    def channel_list(self):
        return self.rocket.channels_list().json()
    
    def group_list(self):
        return self.rocket.groups_list().json()
    
    def subscriptions_list(self):
        return self.rocket.subscriptions_get().json()
    
    def get_keys(self):
        return self.rocket.e2e_fetchMyKeys().json()



def decrypt_asymmetric(private_key, e2ekey):
    data = {
        "message": e2ekey,
        "privateKey": private_key
    }
    print("data : ", json.dumps(data))
    room_key = requests.post('http://localhost:8080/api/v1/rsa-decrypt-e2ekey', json=data)
    print("room-key: ", room_key.text)
    return room_key.text

def get_e2ekey(request, rid):
    subs = request.subscriptions_list()
    for i in subs['update']:
        data = i
        if data['rid'] == rid:
            print("rid: ", rid, "E2EKey: ", data['E2EKey'])
            e2ekey = data['E2EKey']
            break
    group = request.group_list()
    for val in group['groups']:
        if val['_id'] == rid:
            print("rid ", rid, "E2EKeyId ", val['e2eKeyId'])
            e2eKeyId = val['e2eKeyId']
            break
    print('solution ', e2ekey.split(e2eKeyId, 1)[1])
    return e2ekey.split(e2eKeyId, 1)[1]

def get_room_key(private_key, e2ekey):
    room_key = decrypt_asymmetric(private_key, e2ekey)
    return room_key
    
def decrypt_symmetric(master_key, private_key):
    data = {
        "master_key": master_key,
        "private_key": private_key
    }
    private_decrypted = requests.post('http://localhost:8080/api/v1/decrypt-private-key', json=data)
    pem_data = private_decrypted.json()['pem_return']
    print("pem_data: ", json.loads(pem_data)['private_key'])
    return json.loads(pem_data)['private_key']

def get_master_key(password, userid):
    data = {
        "password": password,
        "userId": userid
    }
    master_key = requests.post('http://localhost:8080/api/v1/pbkdf2-master-key', json=data)  
    print("response  ", master_key.status_code)
    print("master_key ", master_key.text)
    return master_key.text

def get_private_key(request, master_key ):
    private_key = request.get_keys()
    private_key_enc = json.loads(json.loads(private_key['message'])['result']['private_key'])['$binary']
    return decrypt_symmetric(master_key, private_key_enc)

def execute_msg_decryption(room_key, filepath):
    command = "node ../msg_parser.ts "+filepath+" "+room_key
    print(command)
    os.system(command)
    #os.system("node ../msg_parser.ts ../file.txt 2222a3beccc315621ad145ae74e7a976")
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=str, required=True)
    parser.add_argument('--user', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--x-user-id', type=str, required=False)
    parser.add_argument('--x-auth-token', type=str, required=False)
    args = parser.parse_args()
    print("Automation process: ")
    import requests
    session = requests.Session()
    session.verify = False
    if args.user and args.password:
        request = RequestServer(args.server, args.user, args.password, None, None, session=session)
    else:
        request = RequestServer(args.server, None, None, args.x_user_id, args.x_auth_token, session=session)
    user_data = request.login()
    print("Success connection !\n\n")
    password = input("user E2E credentials: ")
    #password = "blonde distant plume mixer sunset"
    userid = input("userId: ")
    #userid = "9pqcSnEPqHZdrgS9i"
    groupid = input("groupid: ")
    #groupid = "DSnQMgn66KzNCp7fZ"
    print("User credentials: ", password)
    print("uid: ", userid)
    print("rid: ", groupid)
    master_key = get_master_key(password, userid)
    private_key = get_private_key(request, master_key)
    e2ekey = get_e2ekey(request, groupid)
    room_key = get_room_key(private_key, e2ekey)
    filepath = input("set messages file path ")
    #filepath = "../file.txt"
    execute_msg_decryption(room_key, filepath)



if __name__ == "__main__":
    main()
