package top.lukeewin.jwtdemo.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author Luke Ewin
 * @date 2024/2/19 16:21
 * @blog blog.lukeewin.top
 */
@Target({ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Auth {
    boolean require() default true;
}
