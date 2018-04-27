package com.sc.jwt.security.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
 
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JSONUtils {
	
	static ObjectMapper mapper = new ObjectMapper();
	 
	 public static String toJSON(Object o) {
	  String result = "";
	  if (o != null) {
	   ByteArrayOutputStream out = new ByteArrayOutputStream();
	   try {
	    mapper.writeValue(out, o);
	   } catch (JsonGenerationException e) {
	    e.printStackTrace();
	   } catch (JsonMappingException e) {
	    e.printStackTrace();
	   } catch (IOException e) {
	    e.printStackTrace();
	   }
	   try {
	    result = out.toString("UTF-8");
	   } catch (UnsupportedEncodingException e) {
	    e.printStackTrace();
	   }
	  }
	  return result;
	 }
	 
//	 public static <T> T parseJSON(String jsonString, Class<T> beanClass)
//	   throws JsonParseException, JsonMappingException, IOException {
//	  return (T) mapper.readValue(jsonString, beanClass);
//	 }

}
