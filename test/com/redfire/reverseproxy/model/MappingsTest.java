package com.redfire.reverseproxy.model;

import static org.junit.Assert.*;

import org.junit.Test;

import com.redfire.reverseproxy.model.Mappings;

public class MappingsTest {

  @Test public void testfindByProxyUrl() {
    Mappings mappings= ModelFactory.MAPPINGS;
    assertEquals(mappings.get(0), mappings.findByProxyUrl("http://localhost:8080/rp/maps/1"));
    assertEquals(mappings.get(1), mappings.findByProxyUrl("http://localhost:8080/rp/fb/2"));
  }
  
  @Test public void testfindByHiddenUrl() {
    Mappings mappings= ModelFactory.MAPPINGS;
    assertEquals(mappings.get(0), mappings.findByHiddenUrl("http://maps.google.com/1"));
    assertEquals(mappings.get(1), mappings.findByHiddenUrl("http://www.facebook.com/2"));
  }
  
  
}
