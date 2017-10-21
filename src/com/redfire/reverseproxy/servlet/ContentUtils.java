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
import java.io.InputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;

import com.google.common.base.Throwables;

public class ContentUtils {

  public static void copyBinary(HttpEntity entity, ServletResponse response) {
    try {
      InputStream content = entity.getContent();
      ServletOutputStream outputStream = response.getOutputStream();
      IOUtils.copy(content, outputStream);
    } catch (IOException e) {
      Throwables.propagate(e);
    }
  }
  
  public static void copyText(String text, ServletResponse response, ContentType contentType) {
    //response.setCharacterEncoding(contentType.charset);
	response.setCharacterEncoding("UTF-8");
    response.setContentType(contentType.value);
    try{
    	 int length=text.getBytes("UTF-8").length;
         response.setContentLength(length);
    }catch (Exception e) {
        System.err.println("转码异常  utf-8");
    }
    try{
      response.getWriter().print(text);
    } catch (IOException e) {
      Throwables.propagate(e);
    }
  }
  
  public static String getContentText(HttpEntity entity, String charset) {
    try {
      return IOUtils.toString(entity.getContent(), charset);
    } catch (IOException e) {
      Throwables.propagate(e);
      return null;
    }
  }
  
}
