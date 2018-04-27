package com.sc.jwt.security.token;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Clock;
import io.jsonwebtoken.ExpiredJwtException;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

import org.junit.Test;

public class JwtTokenGenratorTest {

	   private static final String TEST_USERNAME = "remi";

	    @Mock
	    private Clock clockMock;

	    @InjectMocks
	    private JwtTokenGenrator jwtToken;

	    @Before
	    public void init() {
	        MockitoAnnotations.initMocks(this);
	    }

	    @Test
	    public void testGenerateTokenForDifferentCreationDates() throws Exception {
	    	 
	    	 final Calendar yesterday = Calendar.getInstance();
	    	 final Calendar now = Calendar.getInstance(); 
	    	 yesterday.add(Calendar.DATE, -1);
	    	 
	    	when(clockMock.now())
	            .thenReturn(yesterday.getTime())
	            .thenReturn(now.getTime());

	        final String token = createToken();
	        final String laterToken = createToken();

	        assertNotSame(token, laterToken);

	    }

	    @Test
	    public void getUsernameFromToken() throws Exception {
	    	 final Calendar cal = Calendar.getInstance();
	        when(clockMock.now()).thenReturn(cal.getTime());

	        final String token = createToken();

	        assertThat(jwtToken.getUsernameFromToken(token),  is(TEST_USERNAME));
	    }

	    
	    private String createToken() {
	    	JwtAuthUser jwtAuthUser = new JwtAuthUser();
	    	List<JwtAuthPermission> permissions = new ArrayList<>();;
	    	JwtAuthPermission  jwtAuthPermission = new JwtAuthPermission();
	    	
	    	jwtAuthPermission.setId(1L);
	    	jwtAuthPermission.setCode("VIDEO_UNIVERSAL");
	    
	    	
	    	permissions.add(jwtAuthPermission); 
	    	
	    	jwtAuthUser.setId(1L);
	    	jwtAuthUser.setLogin("remi");
	    	jwtAuthUser.setName("remi");
	    	jwtAuthUser.setFirstName("remi");
	    	jwtAuthUser.setEmail("remi@canal-plus.fr");
	    	jwtAuthUser.setPermissions(permissions);
	        return jwtToken.generateToken(jwtAuthUser);
	    }

}
