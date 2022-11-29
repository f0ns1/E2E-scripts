package com.rocketchat.hacking.beans;

public class HMACBean {
    public String text = null;
    public String key = null;

    // getters && setters
    public String getText(){
        return this.text;
    }
    public void setText(String text){
        this.text = text;
    }

    public String getKey(){
        return this.key;
    }
    public void setKey(String key){
        this.key = key;
    }
}
