package top.lukeewin.jwtdemo.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.lukeewin.jwtdemo.annotation.Auth;
import top.lukeewin.jwtdemo.utils.R;

/**
 * @author Luke Ewin
 * @date 2024/2/20 13:56
 * @blog blog.lukeewin.top
 */
@RestController
@RequestMapping("/test")
public class TestController {

    @Auth
    @PostMapping("/hello")
    public R<?> hello() {
        return R.ok("登录成功");
    }

    @PostMapping("/hi")
    public R<?> hi() {
        return R.ok("登录成功");
    }
}
