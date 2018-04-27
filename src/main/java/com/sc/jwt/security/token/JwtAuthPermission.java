package com.sc.jwt.security.token;

import com.fasterxml.jackson.annotation.JsonInclude;

public class JwtAuthPermission {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Long id;

    private String code;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	@Override
	public String toString() {
		return "JwtAuthPermissionLightDto [id=" + id + ", code=" + code + "]";
	}
    
    
}
