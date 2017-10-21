package com.redfire.reverseproxy.utils;

import static org.junit.Assert.*;

import org.junit.Test;

import com.redfire.reverseproxy.utils.PropertiesFile;

public class PropertiesFileTest {
  private static final String FILE= "reverseProxy.test.properties";
  
  @Test
  public void testSubset() {
    PropertiesFile propertiesFile= new PropertiesFile(FILE);
    PropertiesFile subset = propertiesFile.subset("mapping");
    assertEquals(5, subset.getProperties().size());
  }

}
