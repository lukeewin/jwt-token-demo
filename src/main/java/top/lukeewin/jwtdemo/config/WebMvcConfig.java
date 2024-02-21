package top.lukeewin.jwtdemo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import top.lukeewin.jwtdemo.interceptor.CrossInterceptorHandler;
import top.lukeewin.jwtdemo.interceptor.LoginInterceptor;

/**
 * @author Luke Ewin
 * @date 2024/2/19 17:51
 * @blog blog.lukeewin.top
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new CrossInterceptorHandler()).addPathPatterns(new String[] {"/**"});
        registry.addInterceptor(new LoginInterceptor()).addPathPatterns("/**").excludePathPatterns("/user/login", "/error/**");
    }
}
