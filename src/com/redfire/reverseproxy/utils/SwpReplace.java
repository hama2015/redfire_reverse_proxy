package com.redfire.reverseproxy.utils;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpHost;

import com.redfire.reverseproxy.model.Mapping;

public class SwpReplace {
  public static String  replaceLocalHeader(String headerValue,HttpServletRequest httpLocalRequest){

	   HttpHost targetHost=(HttpHost) httpLocalRequest.getAttribute("SwpProxyFilter.targetHost");
	   Mapping mapping =(Mapping) httpLocalRequest.getAttribute("MAPPING");
	   
	   String hiddenDomain=mapping.hiddenDomain;
	   String replaceLocalPath=mapping.proxyDomain+mapping.proxyResource;
	   headerValue=headerValue.replace(replaceLocalPath ,hiddenDomain);
	   
	   if (targetHost.getPort()== -1||targetHost.getPort()==80||targetHost.getPort()==443){
		     String hiddenDomain2= hiddenDomain.replace(":80/", "/");
		     hiddenDomain2= hiddenDomain2.replace(":443/", "/");
		     if(!hiddenDomain2.equals(hiddenDomain)){
		    	 headerValue=  headerValue.replace(replaceLocalPath ,hiddenDomain);
		     }
	   }
	   
	   return headerValue;
  }
  public static String  replaceRemoteHeader(String headerValue,HttpServletRequest httpLocalRequest){
	  HttpHost targetHost=(HttpHost) httpLocalRequest.getAttribute("SwpProxyFilter.targetHost");
	   Mapping mapping =(Mapping) httpLocalRequest.getAttribute("MAPPING");
	   
	   String hiddenDomain=mapping.hiddenDomain;
	   String replaceLocalPath=mapping.proxyDomain+mapping.proxyResource;
	   headerValue=headerValue.replace(hiddenDomain,replaceLocalPath);
	   
	   if (targetHost.getPort()== -1||targetHost.getPort()==80||targetHost.getPort()==443){
		     String hiddenDomain2= hiddenDomain.replace(":80/", "/");
		     hiddenDomain2= hiddenDomain2.replace(":443/", "/");
		     if(!hiddenDomain2.equals(hiddenDomain)){
		    	 headerValue=  headerValue.replace(hiddenDomain2,replaceLocalPath );
		     }
	   }
	   
	   return headerValue;
  }
  public static String  replaceRemoteText(String text,HttpServletRequest httpLocalRequest){
	   HttpHost targetHost=(HttpHost) httpLocalRequest.getAttribute("SwpProxyFilter.targetHost");
	   Mapping mapping =(Mapping) httpLocalRequest.getAttribute("MAPPING");
	   
	   String hiddenDomain=mapping.hiddenDomain;
	   String proxyDomian=mapping.proxyDomain+mapping.proxyResource;
	   text=text.replaceAll(hiddenDomain,proxyDomian);
	   if (targetHost.getPort()== -1||targetHost.getPort()==80||targetHost.getPort()==443){
		     String hiddenDomain2= hiddenDomain.replace(":80/", "/");
		     hiddenDomain2= hiddenDomain2.replace(":443/", "/");
		     if(!hiddenDomain2.equals(hiddenDomain)){
		        text=  text.replaceAll(hiddenDomain,proxyDomian );
		     }
	   }
	   return text;
  }
}
