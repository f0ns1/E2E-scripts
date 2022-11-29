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
    
    def channel_list(self):
        return json2html.convert(self.rocket.channels_list().json())
    
    def group_list(self):
        return json2html.convert(self.rocket.groups_list().json())
    
    def subscriptions_list(self):
        return json2html.convert(self.rocket.subscriptions_get().json())
    def get_keys(self):
        return json2html.convert(self.rocket.e2e_fetchMyKeys().json())
    
    def channels_history(self):
        retr = []
        for i,j in self.rocket.channels_list().json().items():
            try:
                for data in j:
                    if "_id" in data:
                        channel_name = data["_id"]
                        resp = self.rocket.channels_history(channel_name, count=100).json()
                        retr.append(resp)
            except:
                pass
        return json2html.convert(retr)
    
    def groups_history(self):
        retr =[]
        for i,j in self.rocket.groups_list().json().items():
            try:
                for pos in range(len(j)):
                    try:
                        data = j[pos]
                        if "_id" in data:
                            group_name = data["_id"]
                            resp = self.rocket.groups_history(group_name).json()
                            retr.append(resp)
                    except:
                        pass
            except:
                pass
        return json2html.convert(retr)
    
    def user_list(self):
        return json2html.convert(self.rocket.users_list().json())
        
def to_file(filename, data):
    f= open(filename,"w+")
    f.write(data)
    f.close()
    print("\t\tDumping data to file ==> ",filename)

def dump_data(request):
    to_file("./dump_dir/user_ownkeys.html",request.get_keys())
    to_file("./dump_dir/channel_list.html",request.channel_list())
    to_file("./dump_dir/group_list.html",request.group_list())
    to_file("./dump_dir/subscription_list.html",request.subscriptions_list())
    to_file("./dump_dir/users_list.html",request.user_list())
    to_file("./dump_dir/channels_history.html",request.channels_history())
    to_file("./dump_dir/groups_history.html",request.groups_history())
    
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=str, required=True)
    parser.add_argument('--user', type=str, required=False)
    parser.add_argument('--password', type=str, required=False)
    parser.add_argument('--x-user-id', type=str, required=False)
    parser.add_argument('--x-auth-token', type=str, required=False)
    args = parser.parse_args()
    print("\t\t RocketChat:::::::>  script")
    import requests
    session = requests.Session()
    session.verify = False
    if args.user and args.password:
        request = RequestServer(args.server, args.user, args.password, None,None,session=session )
    else:
        request = RequestServer(args.server, None, None, args.x_user_id, args.x_auth_token, session=session)
    user_data=request.login()
    try: 
        os.mkdir("dump_dir") 
    except OSError as error: 
        pass  
    to_file("./dump_dir/user.html", user_data)
    dump_data(request)
        


if __name__ == "__main__":
    main()