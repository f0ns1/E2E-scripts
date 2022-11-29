package com.rocketchat.hacking.beans;

public class PrivateKeyBean {
	
	private String private_key=null;
	private String master_key=null;
	private String pem_return=null;
	
	//Getters && setters
	public String getPrivate_key() {
		return private_key;
	}
	public void setPrivate_key(String private_key) {
		this.private_key = private_key;
	}
	public String getMaster_key() {
		return master_key;
	}
	public void setMaster_key(String master_key) {
		this.master_key = master_key;
	}
	public String getPem_return() {
		return pem_return;
	}
	public void setPem_return(String pem_return) {
		this.pem_return = pem_return;
	}

	

	
	
}
