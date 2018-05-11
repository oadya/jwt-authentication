package com.sc.jwt.security.token;

import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationResponse {
	
    private static final long serialVersionUID = 1250166508152483573L;

    private String token;

	public JwtAuthenticationResponse() {
	}
	
	public JwtAuthenticationResponse(String token) {
		super();
		this.token = token;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
    

}
