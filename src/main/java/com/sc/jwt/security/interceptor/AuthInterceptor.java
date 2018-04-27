package com.sc.jwt.security.interceptor;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import com.sc.jwt.security.token.JwtTokenGenrator;
import com.sc.jwt.security.util.SecurityConstants;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

public class AuthInterceptor implements HandlerInterceptor {

	   
	private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());
	   
    @Autowired
	private JwtTokenGenrator jwtToken;
	    
	public static final String CREDENTIALS_NAME = "Access-Control-Allow-Credentials";
	public static final String ORIGIN_NAME = "Access-Control-Allow-Origin";
	public static final String METHODS_NAME = "Access-Control-Allow-Methods";
	public static final String HEADERS_NAME = "Access-Control-Allow-Headers";
	public static final String MAX_AGE_NAME = "Access-Control-Max-Age";
	
	 String authToken ;
	 String username ;

	@SuppressWarnings("unused")
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		
		LOGGER.debug("Request Method is : '{}'", request.getMethod());
		
		 if("OPTIONS".equals(request.getMethod())) {
		      // Parametre pour les requetes CORS(Cross-origin resource sharing)
			  response.setHeader(CREDENTIALS_NAME, "true");
			  response.setHeader(ORIGIN_NAME, "*");
			  response.setHeader(METHODS_NAME, "GET, OPTIONS, POST, PUT, DELETE");
			  response.setHeader(HEADERS_NAME, "Accept, Accept-Encoding, Accept-Language, Access-Control-Request-Method, Access-Control-Request-Headers, Authorization, Connection, Content-Type, Host,Origin, Referer, Token-Id, User-Agent, X-Requested-With");
			  response.setHeader(MAX_AGE_NAME, "3600");
			  return true;	
			  
		 }
		 if("GET".equals(request.getMethod()) && request.getRequestURI().endsWith("login")) {
			 return true;	
		 }
		 else {	
			  
				LOGGER.debug("authentication process for url : '{}'", request.getRequestURI());
				
				final String requestHeader = request.getHeader(SecurityConstants.TOKEN_HEADER_KEY); 
				
				if(requestHeader != null && requestHeader.startsWith(SecurityConstants.TOKEN_PREFIX)) {
					
					authToken = requestHeader.replace(SecurityConstants.TOKEN_PREFIX,"").trim();
				    				 
				           try {
				        	   username = jwtToken.getUsernameFromToken(authToken);
				                
				            } catch (IllegalArgumentException e) {
				            	LOGGER.error("an error occured during getting username from token", e);
				            } catch (ExpiredJwtException e) {
				            	LOGGER.warn("the token is expired and not valid", e);
				            } catch(SignatureException e) {
				            	LOGGER.error("Authentication Failed. Username or Password not valid.");
				            } 
			           
				} else {			 
					LOGGER.warn("couldn't find bearer string, will ignore the header");	
				}
						
				LOGGER.debug("Check validity of the token for user '{}'", username);
				
			    if(username != null) {	

				    if(jwtToken.validateToken(authToken)) {
						
					 LOGGER.info("token verification is OK for user '{}'", username);
					 return true;
					}
				}
			    LOGGER.info("token verification failed for user '{}'", username);
				return false;
 		  }
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			ModelAndView modelAndView) throws Exception {
          //nothing to do
	}

	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
			throws Exception {
		   //nothing to do
	}

}
