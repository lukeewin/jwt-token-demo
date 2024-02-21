package top.lukeewin.jwtdemo.entity;

import lombok.Data;

/**
 * @author Luke Ewin
 * @date 2024/2/20 9:42
 * @blog blog.lukeewin.top
 */
@Data
public class User {
    private String userName;
    private String password;
    private String token;
}
