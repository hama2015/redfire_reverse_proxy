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
package com.redfire.reverseproxy.servlet;

import java.io.IOException;

import javax.servlet.*;
import javax.servlet.http.*;

import org.apache.http.*;
import org.apache.http.client.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

import com.redfire.reverseproxy.model.Mapping;
import com.redfire.reverseproxy.text.UrlMapper;
import com.redfire.reverseproxy.utils.Tuple2;

public class ProxyFilter implements Filter {

  public void init(FilterConfig filterConfig) throws ServletException {
    
  }
  
  public void destroy() {
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
          throws IOException, ServletException {
   
	if (!isHttp(request, response)) return;
    
    Tuple2<Mapping, String> mapped = mapUrlProxyToHidden(request);
    if (mapped.isNull()) {
      chain.doFilter(request, response);
      return;
    }
    
    executeRequest(response, mapped.e1, mapped.e2);
  }
  
  private static boolean isHttp(ServletRequest request, ServletResponse response) {
    return (request instanceof HttpServletRequest) && (response instanceof HttpServletResponse);
  }
  
  private static Tuple2<Mapping, String> mapUrlProxyToHidden(ServletRequest request) {
	    //本地url   
	    String oldUrl = ((HttpServletRequest)request).getRequestURL().toString();
	    return UrlMapper.mapFullUrlProxyToHidden(oldUrl);
  }

  
  private static void executeRequest(ServletResponse response, Mapping mapping, String newUrl) 
          throws IOException, ClientProtocolException {
    //System.out.println(newUrl);
    HttpClient httpclient = new DefaultHttpClient();
    HttpGet httpget = new HttpGet(newUrl);
    HttpResponse r = httpclient.execute(httpget);
    HttpEntity entity = r.getEntity();
    
    ContentTranslator contentTranslator= new ContentTranslator(mapping, newUrl);
    contentTranslator.translate(entity, response);
  }

  
}