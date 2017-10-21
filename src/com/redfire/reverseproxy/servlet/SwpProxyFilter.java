/*
 * Copyright MITRE
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.redfire.reverseproxy.servlet;
import javax.servlet.*;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.AbortableHttpRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.HeaderGroup;
import org.apache.http.util.EntityUtils;
import org.apache.tomcat.util.http.Cookies;

import com.google.common.base.Throwables;
import com.redfire.reverseproxy.model.Mapping;
import com.redfire.reverseproxy.text.UrlMapper;
import com.redfire.reverseproxy.utils.SwpReplace;
import com.redfire.reverseproxy.utils.Tuple2;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.URI;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;
import java.util.Map;

/**
 * An HTTP reverse proxy/gateway servlet. It is designed to be extended for customization
 * if desired. Most of the work is handled by
 * <a href="http://hc.apache.org/httpcomponents-client-ga/">Apache HttpClient</a>.
 * <p>
 *   There are alternatives to a servlet based proxy such as Apache mod_proxy if that is available to you. However
 *   this servlet is easily customizable by Java, secure-able by your web application's security (e.g. spring-security),
 *   portable across servlet engines, and is embeddable into another web application.
 * </p>
 * <p>
 *   Inspiration: http://httpd.apache.org/docs/2.0/mod/mod_proxy.html
 * </p>
 *
 * @author David Smiley dsmiley@mitre.org
 */
public class SwpProxyFilter implements Filter {

  /* INIT PARAMETER NAME CONSTANTS */

  /** A boolean parameter name to enable logging of input and target URLs to the servlet log. */
  public static final String P_LOG = "log";

  /** A boolean parameter name to enable forwarding of the client IP  */
  public static final String P_FORWARDEDFOR = "forwardip";

  /** A boolean parameter name to keep HOST parameter as-is  */
  public static final String P_PRESERVEHOST = "preserveHost";

  /** A boolean parameter name to keep COOKIES as-is  */
  public static final String P_PRESERVECOOKIES = "preserveCookies";

  /** A boolean parameter name to have auto-handle redirects */
  public static final String P_HANDLEREDIRECTS = "http.protocol.handle-redirects"; // ClientPNames.HANDLE_REDIRECTS

  /** A integer parameter name to set the socket connection timeout (millis) */
  public static final String P_CONNECTTIMEOUT = "http.socket.timeout"; // CoreConnectionPNames.SO_TIMEOUT

  /** A integer parameter name to set the socket read timeout (millis) */
  public static final String P_READTIMEOUT = "http.read.timeout";
  
  /** The parameter name for the target (destination) URI to proxy to. */
  protected static final String P_TARGET_URI = "targetUri";
  protected static final String ATTR_TARGET_URI = "SwpProxyFilter.targetUri";
  protected static final String ATTR_TARGET_HOST ="SwpProxyFilter.targetHost";

  /* MISC */

  protected boolean doLog = true;
  protected boolean doForwardIP = true;
  /** User agents shouldn't send the url fragment but what if it does? */
  protected boolean doSendUrlFragment = true;
  protected boolean doPreserveHost = false;
  protected boolean doPreserveCookies = false;
  protected boolean doHandleRedirects = true;
  protected int connectTimeout = -1;
  protected int readTimeout = -1;
  //These next 3 are cached here, and should only be referred to in initialization logic. See the
  // ATTR_* parameters.
  /** From the configured parameter "targetUri". */
//  protected String targetUri;
//  protected URI targetUriObj;//new URI(targetUri)
//  protected HttpHost targetHost;//URIUtils.extractHost(targetUriObj);



  protected String getTargetUri(HttpServletRequest httpLocalRequest) {
     return (String) httpLocalRequest.getAttribute(ATTR_TARGET_URI);
  }

  protected HttpHost getTargetHost(HttpServletRequest httpLocalResponse) {
    return (HttpHost) httpLocalResponse.getAttribute(ATTR_TARGET_HOST);
  }

  public void logLocalRequest(HttpServletRequest httpLocalRequest ,Tuple2<Mapping, String> mapped){
	     if(!doLog)    return ;
	     System.out.println("  localUrl:"+httpLocalRequest.getRequestURL().toString());
	     System.out.println("  localMethod:"+httpLocalRequest.getMethod());
	     System.out.println("  local header Content-Length:"+httpLocalRequest.getHeader(HttpHeaders.CONTENT_LENGTH));
	     
	     Enumeration<String> enumerationOfHeaderNames = httpLocalRequest.getHeaderNames();
	     System.out.println("---local header---");
	     while (enumerationOfHeaderNames.hasMoreElements()) {
	       String headerName = enumerationOfHeaderNames.nextElement();
	  
	       System.out.print(headerName +":");
	       Enumeration<String> headers = httpLocalRequest.getHeaders(headerName);
	       while (headers.hasMoreElements()) {//sometimes more than one value
	    	   String headerVa= headers.nextElement();
	    	   System.out.print(headerVa +",");
	       }
	       System.out.println();
	     }
	     System.out.println("---local header---");
  }
  private void logProxyRequest(String proxyRequestUri, HttpRequest proxyRequest) {
	    if(!doLog)    return ;
	    System.out.println("--proxy Uri "+proxyRequestUri);
	    Header[] allHeader = proxyRequest.getAllHeaders();
	    System.out.println("---proxy req header---");
	    for(Header header :allHeader){
	      System.out.println(header.getName() +":"+header.getValue());
	    }
	
  }



  private void logProxyResponse(HttpResponse proxyResponse) {
	     if(!doLog)    return ;
		 Header[] allHeader = proxyResponse.getAllHeaders();
		 int statusCode = proxyResponse.getStatusLine().getStatusCode();
	     System.out.println("---proxy resp header---"+statusCode);
	     for(Header header :allHeader){
	      System.out.println(header.getName() +":"+header.getValue());
	     }
		
  }
  private void loglocalResponse(HttpServletResponse httpLocalResponse) {
	     if(!doLog)    return ;
	       System.out.println("---local resp header---");
	     if(httpLocalResponse instanceof SwpHttpServletResponseWrapper){
		   SwpHttpServletResponseWrapper httpLocalResponseWrapper=(SwpHttpServletResponseWrapper)httpLocalResponse;
	       Map<String,String> headerMap=httpLocalResponseWrapper.getHeaderMap();
	       for(String key:headerMap.keySet()){
	    	   System.out.println(key+":"+headerMap.get(key)); 
	       }
	       List<Cookie> cookies=httpLocalResponseWrapper.getCookieList();
	       for(Cookie c:cookies){
	    	   System.out.println(c.getName()+":"+c.getValue() + " path:" +c.getPath()); 
	       }
	     }
	  
		
  }
  public void doFilter(ServletRequest localRequest, ServletResponse localResponse, FilterChain chain) 
          throws IOException, ServletException {
    if (!isHttp(localRequest, localResponse)) return;
    
     HttpServletRequest httpLocalRequest=(HttpServletRequest)localRequest;
     HttpServletResponse httpLocalResponse=
    		 new SwpHttpServletResponseWrapper((HttpServletResponse)localResponse);
    
     String localUrl=httpLocalRequest.getRequestURL().toString();
    

    // mapping  ,newUrl
     Tuple2<Mapping, String> mapped = mapUrlProxyToHidden(localUrl);

     if (mapped.isNull()) {
       chain.doFilter(httpLocalRequest, httpLocalResponse);
       return;
     }
     
     logLocalRequest(httpLocalRequest,mapped);
     
     String proxyUrl=mapped.e2;
     executeRequest(httpLocalRequest,httpLocalResponse, mapped.e1, proxyUrl);
  }
  
  private static boolean isHttp(ServletRequest request, ServletResponse response) {
    return (request instanceof HttpServletRequest) && (response instanceof HttpServletResponse);
  }
  
  private static Tuple2<Mapping, String> mapUrlProxyToHidden(String oldUrl) {
    return UrlMapper.mapFullUrlProxyToHidden(oldUrl);
  }
  protected RequestConfig buildRequestConfig() {
    RequestConfig.Builder builder = RequestConfig.custom()
            .setRedirectsEnabled(doHandleRedirects)
            .setCookieSpec(CookieSpecs.IGNORE_COOKIES) // we handle them in the servlet instead
            .setConnectTimeout(connectTimeout)
            .setSocketTimeout(readTimeout);
    return builder.build();
  }

  /** Called from {@link #init(javax.servlet.ServletConfig)}.
   *  HttpClient offers many opportunities for customization.
   *  In any case, it should be thread-safe.
   **/
  protected HttpClient createHttpClient(final RequestConfig requestConfig) {
    return HttpClientBuilder.create()
            .setDefaultRequestConfig(requestConfig).build();
  }


  public void log(String err,Exception e){
	 
  }
  public void destroy() {
   
  }
  protected  void executeRequest(HttpServletRequest httpLocalRequest,
		  HttpServletResponse httpLocalResponse
		  , Mapping mapping, String targetUri)
        throws ServletException, IOException {
 
	    URI targetUriObj=null;
	    if (targetUri == null)
	      throw new ServletException(P_TARGET_URI+" is required.");
	    //test it's valid
	    try {
	      targetUriObj = new URI(targetUri);
	    } catch (Exception e) {
	      throw new ServletException("Trying to process targetUri init parameter: "+e,e);
	    }
	    
	HttpHost targetHost = URIUtils.extractHost(targetUriObj);
	httpLocalRequest.setAttribute(ATTR_TARGET_URI, targetUri);
	httpLocalRequest.setAttribute(ATTR_TARGET_HOST, targetHost);
	httpLocalRequest.setAttribute("MAPPING", mapping);
    // Make the Request
    //note: we won't transfer the protocol version because I'm not sure it would truly be compatible
    String method = httpLocalRequest.getMethod();
    //带全部参数得远程　路径　
    String proxyRequestUri = rewriteUrlFromRequest(httpLocalRequest);
    

    
    HttpRequest proxyRequest;
    //spec: RFC 2616, sec 4.3: either of these two headers signal that there is a message body.
    if (httpLocalRequest.getHeader(HttpHeaders.CONTENT_LENGTH) != null ||
    	httpLocalRequest.getHeader(HttpHeaders.TRANSFER_ENCODING) != null) {
        proxyRequest = newProxyRequestWithEntity(method, proxyRequestUri, httpLocalRequest);
    } else {
        proxyRequest = new BasicHttpRequest(method, proxyRequestUri);
    }

    copyRequestHeaders(httpLocalRequest, proxyRequest);
    //------代理设置完成 -------------------------------------------------------------------
    //setXForwardedForHeader(httpLocalRequest, proxyRequest);

    logProxyRequest(proxyRequestUri,proxyRequest);
   //-------------------------------------------------------------------------------
    HttpResponse proxyResponse = null;
    try {
      // Execute the request
      proxyResponse = doExecute(httpLocalRequest, httpLocalResponse, proxyRequest);

      // Process the response:

      // Pass the response code. This method with the "reason phrase" is deprecated but it's the
      //   only way to pass the reason along too.
      int statusCode = proxyResponse.getStatusLine().getStatusCode();
      //noinspection deprecation
      httpLocalResponse.setStatus(statusCode, proxyResponse.getStatusLine().getReasonPhrase());

      // Copying response headers to make sure SESSIONID or other Cookie which comes from the remote
      // server will be saved in client when the proxied url was redirected to another one.
      // See issue [#51](https://github.com/mitre/HTTP-Proxy-Servlet/issues/51)
      
       logProxyResponse(proxyResponse);
       copyResponseHeaders(proxyResponse, httpLocalRequest, httpLocalResponse);
       loglocalResponse(httpLocalResponse);
       if (statusCode == HttpServletResponse.SC_NOT_MODIFIED) {
    	  httpLocalResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
       }
       else if (statusCode == HttpServletResponse. SC_MOVED_TEMPORARILY) {
    	  httpLocalResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
      }else if (statusCode == 400) {
    	  httpLocalResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
      }
      else {
    	  
          HttpEntity entity = proxyResponse.getEntity();
    	  ContentTranslator contentTranslator= new ContentTranslator(mapping, targetUri);
          contentTranslator.translate(entity,httpLocalRequest, httpLocalResponse);;
      }

    } catch (Exception e) {
      //abort request, according to best practice with HttpClient
      if (proxyRequest instanceof AbortableHttpRequest) {
        AbortableHttpRequest abortableHttpRequest = (AbortableHttpRequest) proxyRequest;
        abortableHttpRequest.abort();
      }
      if (e instanceof RuntimeException)
        throw (RuntimeException)e;
      if (e instanceof ServletException)
        throw (ServletException)e;
      //noinspection ConstantConditions
      if (e instanceof IOException)
        throw (IOException) e;
      throw new RuntimeException(e);

    } finally {
      // make sure the entire entity was consumed, so the connection is released
      if (proxyResponse != null)
        consumeQuietly(proxyResponse.getEntity());
      //Note: Don't need to close servlet outputStream:
      // http://stackoverflow.com/questions/1159168/should-one-call-close-on-httpservletresponse-getoutputstream-getwriter
    }
  }




protected HttpResponse doExecute(HttpServletRequest httpLocalRequest, HttpServletResponse httpLocalResponse,
                                   HttpRequest proxyRequest) throws IOException {
    if (doLog) {
      log("proxy " + httpLocalRequest.getMethod() + " uri: " + httpLocalRequest.getRequestURI() + " -- " +
              proxyRequest.getRequestLine().getUri(),null);
    }
    HttpClient   proxyClient= createHttpClient(buildRequestConfig());
    return proxyClient.execute(getTargetHost(httpLocalRequest), proxyRequest);
  }

  protected HttpRequest newProxyRequestWithEntity(String method, String proxyRequestUri,
                                                HttpServletRequest servletRequest)
          throws IOException {
    HttpEntityEnclosingRequest eProxyRequest =
            new BasicHttpEntityEnclosingRequest(method, proxyRequestUri);
    // Add the input entity (streamed)
    //  note: we don't bother ensuring we close the servletInputStream since the container handles it
    BasicHttpEntity entity = new BasicHttpEntity();  
    //设置内容  
    entity.setContent(servletRequest.getInputStream());  
    //设置长度  
    long reqLength=getContentLength(servletRequest);
    
    entity.setContentLength(reqLength);  
    //没搞懂chunked这个属性啥意思  
    entity.setChunked(false);  
    eProxyRequest.setEntity(entity);
    return eProxyRequest;
  }

  // Get the header value as a long in order to more correctly proxy very large requests
  private long getContentLength(HttpServletRequest request) {
    String contentLengthHeader = request.getHeader("Content-Length");
    if (contentLengthHeader != null) {
      return Long.parseLong(contentLengthHeader);
    }
    return -1L;
  }

  protected void closeQuietly(Closeable closeable) {
    try {
      closeable.close();
    } catch (IOException e) {
      log(e.getMessage(), e);
    }
  }

  /** HttpClient v4.1 doesn't have the
   * {@link org.apache.http.util.EntityUtils#consumeQuietly(org.apache.http.HttpEntity)} method. */
  protected void consumeQuietly(HttpEntity entity) {
    try {
      EntityUtils.consume(entity);
    } catch (IOException e) {//ignore
      log(e.getMessage(), e);
    }
  }

  /** These are the "hop-by-hop" headers that should not be copied.
   * http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
   * I use an HttpClient HeaderGroup class instead of Set&lt;String&gt; because this
   * approach does case insensitive lookup faster.
   */
  protected static final HeaderGroup hopByHopHeaders;
  static {
    hopByHopHeaders = new HeaderGroup();
    String[] headers = new String[] {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
        "TE", "Trailers", "Transfer-Encoding", "Upgrade","Cache-Control" };
    for (String header : headers) {
      hopByHopHeaders.addHeader(new BasicHeader(header, null));
    }
  }

  /** 
   * Copy request headers from the servlet client to the proxy request. 
   * This is easily overridden to add your own.
   */
  protected void copyRequestHeaders(HttpServletRequest httpLocalRequest
		  , HttpRequest proxyRequest) {
    // Get an Enumeration of all of the header names sent by the client
    @SuppressWarnings("unchecked")
    Enumeration<String> enumerationOfHeaderNames = httpLocalRequest.getHeaderNames();
    
    HttpHost host = getTargetHost(httpLocalRequest);
    String hostPath = host.getHostName();
    if (host.getPort() != -1){
    	hostPath += ":"+host.getPort();
    }
    
    while (enumerationOfHeaderNames.hasMoreElements()) {
      String headerName = enumerationOfHeaderNames.nextElement();
      copyRequestHeader(httpLocalRequest, proxyRequest, headerName,hostPath);
    }
  }

  /**
   * Copy a request header from the servlet client to the proxy request.
   * This is easily overridden to filter out certain headers if desired.
   */
  protected void copyRequestHeader(HttpServletRequest httpLocalRequest, HttpRequest proxyRequest,
                                   String headerName,String hostPath) {
    //Instead the content-length is effectively set via InputStreamEntity
    if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
         return;
    if (hopByHopHeaders.containsHeader(headerName))
         return;

    @SuppressWarnings("unchecked")
    Enumeration<String> headers = httpLocalRequest.getHeaders(headerName);
    while (headers.hasMoreElements()) {//sometimes more than one value
      String headerValue = headers.nextElement();
      // In case the proxy host is running multiple virtual servers,
      // rewrite the Host header to ensure that we get content from
      // the correct virtual server
      //不保持Host 
      if (!doPreserveHost && headerName.equalsIgnoreCase(HttpHeaders.HOST)) {
         headerValue = hostPath;
      } else if (!doPreserveCookies && headerName.equalsIgnoreCase(org.apache.http.cookie.SM.COOKIE)) {
          //删除cookies前缀 
    	  headerValue = getRealCookie(headerValue);
      }
      //referer: http://localhost:8080/rp/lms/app/login/login.jsp
      if("referer".equals(headerName)){
    	  headerValue = SwpReplace.replaceLocalHeader(headerValue,httpLocalRequest); 
      }
      if("origin".equals(headerName)){
    	  if(headerValue.startsWith("https://")){
    		  headerValue = "https://"+hostPath;
    	  }else{
    		  headerValue = "http://"+hostPath;
    	  }
      }
      proxyRequest.addHeader(headerName, headerValue);
    }
  }

  private void setXForwardedForHeader(HttpServletRequest httpLocalRequest,
                                      HttpRequest proxyRequest) {
    if (doForwardIP) {
      String forHeaderName = "X-Forwarded-For";
      String forHeader = httpLocalRequest.getRemoteAddr();
      String existingForHeader = httpLocalRequest.getHeader(forHeaderName);
      if (existingForHeader != null) {
        forHeader = existingForHeader + ", " + forHeader;
      }
      proxyRequest.setHeader(forHeaderName, forHeader);

      String protoHeaderName = "X-Forwarded-Proto";
      String protoHeader = httpLocalRequest.getScheme();
      proxyRequest.setHeader(protoHeaderName, protoHeader);
    }
  }
  /** Copy proxied response headers back to the servlet client. */
  protected void copyResponseHeaders(HttpResponse proxyResponse
		  , HttpServletRequest httpLocalRequest,
                                     HttpServletResponse httpLocalResponse) {
    for (Header header : proxyResponse.getAllHeaders()) {
        copyResponseHeader(httpLocalRequest, httpLocalResponse, header);
    }
  }

  /** Copy a proxied response header back to the servlet client.
   * This is easily overwritten to filter out certain headers if desired.
   */
  protected void copyResponseHeader(HttpServletRequest httpLocalRequest,
                                  HttpServletResponse httpLocalResponse, Header header) {
    String headerName = header.getName();

    // TODO 后期
     //if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
     //     return;
     if (hopByHopHeaders.containsHeader(headerName))
          return;
     String headerValue = header.getValue();
     if (headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE) ||
         headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE2)) {
    	 List<Cookie> servletCookies=changeProxyCookie(httpLocalRequest,headerValue);
         if(servletCookies!=null){
        	 for(Cookie c:servletCookies){
        	   httpLocalResponse.addCookie(c);
        	 }
         }
    	 
    } else if (headerName.equalsIgnoreCase(HttpHeaders.LOCATION)) {
      // LOCATION Header may have to be rewritten.
  	    String locationV = SwpReplace.replaceRemoteHeader(headerValue,httpLocalRequest);
  	    httpLocalResponse.addHeader(headerName,locationV);
    } else {
    	httpLocalResponse.addHeader(headerName, headerValue);
    }
  }

  /** Copy cookie from the proxy to the servlet client.
   *  Replaces cookie path to local path and renames cookie to avoid collisions.
   */
  protected List<Cookie> changeProxyCookie(HttpServletRequest httpLocalRequest, String headerValue) {
    List<HttpCookie> cookies = HttpCookie.parse(headerValue);
    String path = httpLocalRequest.getContextPath(); // path starts with / or is empty string
    path += httpLocalRequest.getServletPath(); // servlet path starts with / or is empty string
    if(path.isEmpty()){
        path = "/";
    }
    List<Cookie> localCookieList=new ArrayList<Cookie>();
    for (HttpCookie cookie : cookies) {
      //set cookie name prefixed w/ a proxy value so it won't collide w/ other cookies
      String proxyCookieName = doPreserveCookies ? cookie.getName() : getCookieNamePrefix(cookie.getName()) + cookie.getName();
      Cookie servletCookie = new Cookie(proxyCookieName, cookie.getValue());
      //servletCookie.setComment(cookie.getComment());
      servletCookie.setMaxAge((int) cookie.getMaxAge());
      servletCookie.setPath(path); //set to the path of the proxy servlet
      // don't set cookie domain
      servletCookie.setSecure(cookie.getSecure());
      servletCookie.setVersion(cookie.getVersion());
      localCookieList.add(servletCookie);
    }
    return localCookieList;
  }

  /** Take any client cookies that were originally from the proxy and prepare them to send to the
   * proxy.  This relies on cookie headers being set correctly according to RFC 6265 Sec 5.4.
   * This also blocks any local cookies from being sent to the proxy.
   */
  protected String getRealCookie(String cookieValue) {
    StringBuilder escapedCookie = new StringBuilder();
    String cookies[] = cookieValue.split("[;,]");
    for (String cookie : cookies) {
      String cookieSplit[] = cookie.split("=");
      if (cookieSplit.length == 2) {
        String cookieName = cookieSplit[0].trim();
        if (cookieName.startsWith(getCookieNamePrefix(cookieName))) {
          cookieName = cookieName.substring(getCookieNamePrefix(cookieName).length());
          if (escapedCookie.length() > 0) {
            escapedCookie.append("; ");
          }
          escapedCookie.append(cookieName).append("=").append(cookieSplit[1].trim());
        }
      }
    }
    return escapedCookie.toString();
  }

  /** The string prefixing rewritten cookies. */
  protected String getCookieNamePrefix(String name) {
    return "swp_Proxy_";
  }
  /** Reads the request URI from {@code servletRequest} and rewrites it, considering targetUri.
   * It's used to make the new request.
   */
  protected String rewriteUrlFromRequest(HttpServletRequest httpLocalRequest) {
    StringBuilder uri = new StringBuilder(500);
    uri.append(getTargetUri(httpLocalRequest));
    // Handle the path given to the servlet
    if (httpLocalRequest.getPathInfo() != null) {//ex: /my/path.html
      uri.append(encodeUriQuery(httpLocalRequest.getPathInfo()));
    }
    // Handle the query string & fragment
    String queryString = httpLocalRequest.getQueryString();//ex:(following '?'): name=value&foo=bar#fragment
    String fragment = null;
    //split off fragment from queryString, updating queryString if found
    if (queryString != null) {
      int fragIdx = queryString.indexOf('#');
      if (fragIdx >= 0) {
        fragment = queryString.substring(fragIdx + 1);
        queryString = queryString.substring(0,fragIdx);
      }
    }

    queryString = rewriteQueryStringFromRequest(httpLocalRequest, queryString);
    if (queryString != null && queryString.length() > 0) {
      uri.append('?');
      uri.append(encodeUriQuery(queryString));
    }

    if (doSendUrlFragment && fragment != null) {
      uri.append('#');
      uri.append(encodeUriQuery(fragment));
    }
    return uri.toString();
  }

  protected String rewriteQueryStringFromRequest(HttpServletRequest httpLocalRequest, String queryString) {
    return queryString;
  }

  /** For a redirect response from the target server, this translates {@code theUrl} to redirect to
   * and translates it to one the original client can use. */
  protected String rewriteUrlFromResponse(HttpServletRequest servletRequest, String theUrl) {
    //TODO document example paths
    final String targetUri = getTargetUri(servletRequest);
    if (theUrl.startsWith(targetUri)) {
      /*-
       * The URL points back to the back-end server.
       * Instead of returning it verbatim we replace the target path with our
       * source path in a way that should instruct the original client to
       * request the URL pointed through this Proxy.
       * We do this by taking the current request and rewriting the path part
       * using this servlet's absolute path and the path from the returned URL
       * after the base target URL.
       */
      StringBuffer curUrl = servletRequest.getRequestURL();//no query
      int pos;
      // Skip the protocol part
      if ((pos = curUrl.indexOf("://"))>=0) {
        // Skip the authority part
        // + 3 to skip the separator between protocol and authority
        if ((pos = curUrl.indexOf("/", pos + 3)) >=0) {
          // Trim everything after the authority part.
          curUrl.setLength(pos);
        }
      }
      // Context path starts with a / if it is not blank
      curUrl.append(servletRequest.getContextPath());
      // Servlet path starts with a / if it is not blank
      curUrl.append(servletRequest.getServletPath());
      curUrl.append(theUrl, targetUri.length(), theUrl.length());
      theUrl = curUrl.toString();
    }
    return theUrl;
  }


  /**
   * Encodes characters in the query or fragment part of the URI.
   *
   * <p>Unfortunately, an incoming URI sometimes has characters disallowed by the spec.  HttpClient
   * insists that the outgoing proxied request has a valid URI because it uses Java's {@link URI}.
   * To be more forgiving, we must escape the problematic characters.  See the URI class for the
   * spec.
   *
   * @param in example: name=value&amp;foo=bar#fragment
   */
  protected static CharSequence encodeUriQuery(CharSequence in) {
    //Note that I can't simply use URI.java to encode because it will escape pre-existing escaped things.
    StringBuilder outBuf = null;
    Formatter formatter = null;
    for(int i = 0; i < in.length(); i++) {
      char c = in.charAt(i);
      boolean escape = true;
      if (c < 128) {
        if (asciiQueryChars.get((int)c)) {
          escape = false;
        }
      } else if (!Character.isISOControl(c) && !Character.isSpaceChar(c)) {//not-ascii
        escape = false;
      }
      if (!escape) {
        if (outBuf != null)
          outBuf.append(c);
      } else {
        //escape
        if (outBuf == null) {
          outBuf = new StringBuilder(in.length() + 5*3);
          outBuf.append(in,0,i);
          formatter = new Formatter(outBuf);
        }
        //leading %, 0 padded, width 2, capital hex
        formatter.format("%%%02X",(int)c);//TODO
      }
    }
    return outBuf != null ? outBuf : in;
  }

  protected static final BitSet asciiQueryChars;
  static {
    char[] c_unreserved = "_-!.~'()*".toCharArray();//plus alphanum
    char[] c_punct = ",;:$&+=".toCharArray();
    char[] c_reserved = "?/[]@".toCharArray();//plus punct

    asciiQueryChars = new BitSet(128);
    for(char c = 'a'; c <= 'z'; c++) asciiQueryChars.set((int)c);
    for(char c = 'A'; c <= 'Z'; c++) asciiQueryChars.set((int)c);
    for(char c = '0'; c <= '9'; c++) asciiQueryChars.set((int)c);
    for(char c : c_unreserved) asciiQueryChars.set((int)c);
    for(char c : c_punct) asciiQueryChars.set((int)c);
    for(char c : c_reserved) asciiQueryChars.set((int)c);

    asciiQueryChars.set((int)'%');//leave existing percent escapes in place
  }

@Override
public void init(FilterConfig filterConfig) throws ServletException {
	    String doLogStr = filterConfig.getInitParameter(P_LOG);
	    if (doLogStr != null) {
	       this.doLog = Boolean.parseBoolean(doLogStr);
	    }
	    String doForwardIPString = filterConfig.getInitParameter(P_FORWARDEDFOR);
	    if (doForwardIPString != null) {
	      this.doForwardIP = Boolean.parseBoolean(doForwardIPString);
	    }

	    String preserveHostString = filterConfig.getInitParameter(P_PRESERVEHOST);
	    if (preserveHostString != null) {
	      this.doPreserveHost = Boolean.parseBoolean(preserveHostString);
	    }

	    String preserveCookiesString = filterConfig.getInitParameter(P_PRESERVECOOKIES);
	    if (preserveCookiesString != null) {
	      this.doPreserveCookies = Boolean.parseBoolean(preserveCookiesString);
	    }

	    String handleRedirectsString = filterConfig.getInitParameter(P_HANDLEREDIRECTS);
	    if (handleRedirectsString != null) {
	      this.doHandleRedirects = Boolean.parseBoolean(handleRedirectsString);
	    }

	    String connectTimeoutString = filterConfig.getInitParameter(P_CONNECTTIMEOUT);
	    if (connectTimeoutString != null) {
	      this.connectTimeout = Integer.parseInt(connectTimeoutString);
	    }
	    
	    String readTimeoutString = filterConfig.getInitParameter(P_READTIMEOUT);
	    if (readTimeoutString != null) {
	      this.readTimeout = Integer.parseInt(readTimeoutString);
	    }
}

  
}
