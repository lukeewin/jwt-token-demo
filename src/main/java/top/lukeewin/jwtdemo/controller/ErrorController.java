package top.lukeewin.jwtdemo.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.lukeewin.jwtdemo.utils.R;
import top.lukeewin.jwtdemo.utils.ResponseEnum;

/**
 * @author Luke Ewin
 * @date 2024/2/20 14:10
 * @blog blog.lukeewin.top
 */
@RestController
@RequestMapping("/error")
public class ErrorController {

    @PostMapping("/token")
    public R<?> token() {
        return R.error(ResponseEnum.NO_TOKEN);
    }

    @PostMapping("/tokenError")
    public R<?> tokenError() {
        return R.error(ResponseEnum.TOKEN_VERIFY_ERROR);
    }
}
