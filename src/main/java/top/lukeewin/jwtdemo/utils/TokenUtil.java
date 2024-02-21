package top.lukeewin.jwtdemo.utils;

import cn.hutool.core.date.DateUtil;
import cn.hutool.json.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

import java.util.Date;

/**
 * @author Luke Ewin
 * @date 2024/2/19 16:59
 * @blog blog.lukeewin.top
 */
public class TokenUtil {

    private final static String ENCRYPT_KEY = "abc123";

    private final static int EXPIRE_TIME = 1;

    private static final String ISSUER = "zhangsan";

    /**
     * 生成 token
     *
     * @param json 要封装到 token 的内容，如果要传递多个参数内容，可以定义为 JSON 或者 Map
     * @return 返回 token
     */
    public static String createToken(JSONObject json) {
        return JWT.create()
                .withSubject(json.toString())
                .withIssuer(ISSUER)
                .withExpiresAt(DateUtil.offsetMinute(new Date(), EXPIRE_TIME))
                .withClaim("test", "123")
                .sign(Algorithm.HMAC256(ENCRYPT_KEY));
    }

    /**
     * 验证 token
     *
     * @param token
     * @return
     */
    public static boolean verifyToken(String token) {
        try {
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(ENCRYPT_KEY))
                    .withIssuer(ISSUER)
                    .build();
            jwtVerifier.verify(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
