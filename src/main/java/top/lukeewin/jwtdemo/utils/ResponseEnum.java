package top.lukeewin.jwtdemo.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * @author Luke Ewin
 * @date 2024/2/19 16:30
 * @blog blog.lukeewin.top
 */
@AllArgsConstructor
@Getter
public enum ResponseEnum {

    SUCCESS(200, "操作成功"),

    FAIL(300,"获取数据失败"),

    USER_EX(301,"用户不存在，请重新登录"),

    ERROR(302,"错误请求"),

    USERNAME_PASSWORD_ERROR(303,"用户名或密码错误"),

    NO_TOKEN(400,"无token，请重新登录"),

    TOKEN_VERIFY_ERROR(401,"token验证失败，请重新登录"),

    TOKEN_EX(402,"token已过期");

    private final Integer code;

    private final String msg;

    public static ResponseEnum getResultCode(Integer code){
        for (ResponseEnum value : ResponseEnum.values()) {
            if (code.equals(value.getCode())){
                return value;
            }
        }
        return ResponseEnum.ERROR;
    }
}
