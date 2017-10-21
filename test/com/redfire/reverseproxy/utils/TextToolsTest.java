package com.redfire.reverseproxy.utils;

import static org.junit.Assert.*;

import org.junit.Test;

import com.redfire.reverseproxy.utils.TextTools;

public class TextToolsTest {

  @Test public void testRemoveControlChars() {
      assertEquals("", TextTools.removeControlChars(null));
      assertEquals("", TextTools.removeControlChars(""));
      assertEquals("  ", TextTools.removeControlChars("  "));
      assertEquals("    ", TextTools.removeControlChars(" \t\n "));
    }
  

}
