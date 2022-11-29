package com.rocketchat.hacking.beans;

public class RSABean {
    public String message= null;
    public String privateKey = null;

    
    //getters && setters

    public String getMessage(){
        return this.message;
    }
    public void setMessage(String messsage){
        this.message= messsage;
    }
    
    public String getPrivateKey(){
        return this.privateKey;
    }
    public void setPrivateKey(String privateKey){
        this.privateKey= privateKey;
    } 

}
