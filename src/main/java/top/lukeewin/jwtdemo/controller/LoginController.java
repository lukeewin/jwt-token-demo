package top.lukeewin.jwtdemo.controller;

import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.lukeewin.jwtdemo.entity.User;
import top.lukeewin.jwtdemo.utils.R;
import top.lukeewin.jwtdemo.utils.ResponseEnum;
import top.lukeewin.jwtdemo.utils.TokenUtil;

/**
 * @author Luke Ewin
 * @date 2024/2/19 17:56
 * @blog blog.lukeewin.top
 */
@RestController
@RequestMapping("/user")
public class LoginController {
    @PostMapping("/login")
    public R<User> login(String userName, String password) {
        if (StringUtils.isNotBlank(userName) && StringUtils.isNotBlank(password)) {
            if ("张三".equals(userName) && "123456".equals(password)) {
                User user = new User();
                JSONObject json = JSONUtil.createObj()
                        .put("name", "zhangsan");
                String token = TokenUtil.createToken(json);
                user.setToken(token);
                return R.ok(user);
            }
        }
        return R.error(ResponseEnum.USERNAME_PASSWORD_ERROR);
    }
}
