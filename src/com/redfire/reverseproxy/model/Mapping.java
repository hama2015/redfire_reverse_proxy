/*
This file is part of Tek271 Reverse Proxy Server.

Tek271 Reverse Proxy Server is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Tek271 Reverse Proxy Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with Tek271 Reverse Proxy Server.  If not, see http://www.gnu.org/licenses/
 */
package com.redfire.reverseproxy.model;

import static org.apache.commons.lang.StringUtils.*;

import java.util.List;

import com.google.common.base.*;
import com.google.common.collect.Lists;
import static com.google.common.base.Preconditions.*;

public class Mapping {
  public final String hiddenDomain;//  远程地址
  public final String proxyDomain;//   本地地址
  public final String proxyResource;// 本地资源
  public final String proxy;//本地代理地址 
  
  public Mapping(String mapping) {
    checkArgument(isNotBlank(mapping), "mapping must contain a value");
    mapping= trimToEmpty(mapping);
    List<String> items= Lists.newArrayList(Splitter.on(',').trimResults().split(mapping));
    checkArgument(items.size()==3, "mappings must have 3 comma-separated values");
    
    hiddenDomain= items.get(0);
    proxyDomain= items.get(1);
    proxyResource= items.get(2);
    proxy= proxyDomain + proxyResource;
  }
  
  private static final String SEP = "://";
  
  public String mapProxyToHidden(String proxyUrl) {
    String path = extractPath(proxyUrl, proxyDomain, proxyResource);
     //http|https :// 
     return extractProtocol(proxyUrl) + SEP + hiddenDomain + path; 
  }
  
  public String mapHiddenToProxy(String hiddenUrl) {
    String path = extractPath(hiddenUrl, hiddenDomain, "");
    return extractProtocol(hiddenUrl) + SEP + proxy + path;
  }
  
  private static String extractProtocol(String url) {
	  //http|https
     return substringBefore(url, SEP);
  }
  
  private String extractPath(String url, String domain, String resource) {
	  //获取后边得相对地址 
      String prefix= domain + resource;
      return substringAfter(url, prefix);
  }

  @Override
  public String toString() {
	return "Mapping [hiddenDomain=" + hiddenDomain + ", proxyDomain=" + proxyDomain + ", proxyResource=" + proxyResource
			+ ", proxy=" + proxy + "]";
  }
  
 
}
