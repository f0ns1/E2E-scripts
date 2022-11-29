package com.rocketchat.hacking.beans;

public class AESBean {
    public String textBase64=null;
    public String hexIv= null;
    public String hexKey= null;
    public String cipherText= null;

    //getters && setters
    public String getTextBase64(){
        return this.textBase64;
    }
    public void setTextBase64(String textBase64){
        this.textBase64=textBase64;
    }

    public String getHexIv(){
        return this.hexIv;
    }
    public void setHexIv(String hexIv){
        this.hexIv = hexIv;
    }
    
    public String getHexKey(){
        return this.hexKey;
    }
    public void setHexKey(String hexKey){
        this.hexKey= hexKey;
    }

    public String getCipherText(){
        return this.cipherText;
    }
    public void setCipherText(String cipherText){
        this.cipherText=cipherText;
    }

}