package com.sc.jwt.security.token;

import java.util.List;

public class JwtAuthUser {

	private Long id;

	private String login;

	private String email;

	private String name;

	private String firstName;

	private List<JwtAuthPermission> permissions;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public List<JwtAuthPermission> getPermissions() {
		return permissions;
	}

	public void setPermissions(List<JwtAuthPermission> permissions) {
		this.permissions = permissions;
	}

	@Override
	public String toString() {
		return "JwtAuthUser [id=" + id + ", login=" + login + ", email=" + email + ", name=" + name + ", firstName="
				+ firstName + ", permissions=" + permissions + "]";
	}
	
	
}
