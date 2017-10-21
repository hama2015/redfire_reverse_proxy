package com.redfire.reverseproxy.servlet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class SwpHttpServletResponseWrapper extends HttpServletResponseWrapper {
    
	private  Map<String,String> headerMap=new HashMap<String,String>();
	public Map<String, String> getHeaderMap() {
		return headerMap;
	}
	public List<Cookie> getCookieList() {
		return cookieList;
	}
	private  List<Cookie> cookieList=new ArrayList<Cookie>();
 	public SwpHttpServletResponseWrapper(HttpServletResponse response) {
		super(response);
	}
    public void addHeader(String name,String value){
    	headerMap.put(name,value);
    	super.addHeader(name, value);
    }
    public void addCookie(Cookie cookie){
    	cookieList.add(cookie);
    	super.addCookie(cookie);
    }
	
} 
