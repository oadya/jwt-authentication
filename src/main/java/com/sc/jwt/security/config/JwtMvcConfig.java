package com.sc.jwt.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.sc.jwt.security.interceptor.AuthInterceptor;


@EnableWebMvc
@Configuration
@ComponentScan(basePackages = { "com.sc.jwt.security.*" })
public class JwtMvcConfig extends WebMvcConfigurerAdapter {

	
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
				.allowedOrigins("*")
				.allowedMethods("POST", "GET", "OPTIONS", "DELETE", "PUT")
				.allowedHeaders("Accept", "Accept-Encoding", "Accept-Language", "Access-Control-Request-Method",
                        "Access-Control-Request-Headers", "Authorization", "Connection", "Content-Type", "Host",
                        "Origin", "Referer", "Token-Id", "User-Agent", "X-Requested-With")
				.maxAge(3600);
	}
	
	
	@Bean
	public AuthInterceptor getAuthInterceptor() { 
	    return new AuthInterceptor();
	}
	
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(getAuthInterceptor()).addPathPatterns("/**").excludePathPatterns("/login/findUser", "*/swagger-ui.html#/*");
	}

}
