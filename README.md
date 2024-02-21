# 背景

我们在基于`Session`做登录认证的时候，会有一些问题，因为`Session`存储到服务器端，然后通过客户端的`Cookie`进行匹配，如果正确，则通过认证，否则不通过认证。这在简单的系统中可以这么使用，并且难道是最低的，但是如果在大型分布式项目中，如果还是基于`Session`做登录认证的话，就不可行了。这个时候我们可以基于`token`做登录认证。`token`其实就是一个字符串，生成`token`的实现方案有很多种，可以使用`uuid`作为`token`，也可以使用`jwt`作为`token`，其中使用`jwt`实现的方案是最流行的，那么下面将会讲如何在`SpringBoot`中基于`jwt`实现`token`登录认证。

# 1. 引入依赖

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>4.4.0</version>
</dependency>
```

# 2. 自定义注解

自定义一个注解，在需要认证的方法上添加该注解

```java
@Target({ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Auth {
    boolean require() default true;
}
```

# 3. 编写拦截器

通过识别是否在接口上添加`@Auth`注解来确定是否需要登录才能访问。

同时这里需要注意只拦截`HandlerMethod`类型，同时还要考虑放行`BasicErrorController`，因为基本的报错在这个控制器中，如果不放行，那么会看不到报错信息。

```java
public class LoginInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            if (handlerMethod.getBean() instanceof BasicErrorController) {
                return true;
            }
            Auth auth = handlerMethod.getMethod().getAnnotation(Auth.class);
            if (auth != null && auth.require()) {
                String token = request.getHeader("token");
                if (StringUtils.isNotBlank(token)) {
                    if (TokenUtil.verifyToken(token)) { // 校验 token 是否正确
                        return true;
                    } else {
                        request.getRequestDispatcher("/error/tokenError").forward(request, response); // 这里你也可以直接抛出自定义异常，然后在全局异常处理器中处理
                    }
                } else {
                    request.getRequestDispatcher("/error/token").forward(request, response); // 这里你也可以直接抛出自定义异常，然后在全局异常处理器中处理
                }
            } else {
                return true;
            }
        } else {
            return true;
        }
        return false;
    }
}
```

# 4. 定义跨域拦截器

这里是做前后端分离需要做的步骤，解决跨域的方式有好几种，这里使用拦截器的方式解决跨域问题。

```java
public class CrossInterceptorHandler implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET , PUT , OPTIONS");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "x-requested-with,accept,authorization,content-type");
        return true;
    }
}
```

# 5. 定义全局异常处理器

这里没有用到全局异常处理器，不过为了项目的完整性，我还是选择把这些常规的内容写上去。

```java
@RestControllerAdvice
public class GlobalException {

    public final Logger logger = LoggerFactory.getLogger(this.getClass());

    @ExceptionHandler(TokenExpiredException.class)
    public R<?> handleTokenExpiredException(TokenExpiredException e) {
        logger.error("token 已过期");
        logger.error(e.getMessage());
        return R.error(ResponseEnum.TOKEN_EX);
    }
}
```

# 6. 定义工具类

## 6.1 统一错误状态码

编写一个枚举类，统一项目的报错状态码。

```java
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
```

## 6.2 统一响应类

```java
@Data
public class R<T> implements Serializable {

    private static final long serialVersionUID = 56665257244236049L;

    private Integer code;

    private String message;

    private T data;

    private R() {
    }

    public static <T> R<T> ok(T data) {
        R<T> response = new R<>();
        response.setCode(ResponseEnum.SUCCESS.getCode());
        response.setMessage(ResponseEnum.SUCCESS.getMsg());
        response.setData(data);
        return response;
    }

    public static <T> R<T> error(Integer errCode, String errMessage) {
        R<T> response = new R<>();
        response.setCode(errCode);
        response.setMessage(errMessage);
        return response;
    }

    public static <T> R<T> error(ResponseEnum responseEnum) {
        R<T> response = new R<>();
        response.setCode(responseEnum.getCode());
        response.setMessage(responseEnum.getMsg());
        return response;
    }
}
```

## 6.3 Token工具类

通过`TokenUtil`可以生成`token`和验证`token`是否正确。

```java
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

    private final static String ENCRYPT_KEY = "abc123"; // 加密的密钥

    private final static int EXPIRE_TIME = 1; // token 过期时间，单位分钟

    private static final String ISSUER = "zhangsan";

    /**
     * 生成 token
     *
     * @param json 要封装到 token 的内容，如果要传递多个参数内容，可以定义为 JSON 或者 Map
     * @return 返回 token
     */
    public static String createToken(JSONObject json) {
        return JWT.create()
                .withSubject(json.toString()) // 不要把密码封装进去，不安全
                .withIssuer(ISSUER) // 设置发布者
                .withExpiresAt(DateUtil.offsetMinute(new Date(), EXPIRE_TIME)) // 设置过期时间
                .withClaim("test", "123") // 这里是随便设置的内容，类似 Map
                .sign(Algorithm.HMAC256(ENCRYPT_KEY)); // 加密
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
        } catch (Exception e) { // 如果 token 过期会报错 TokenExpiredException
            e.printStackTrace();
            return false;
        }
    }
}
```

# 7. 编写实体类

这里为了简单，并没有与数据库交互。

```java
@Data
public class User {
    private String userName;
    private String password;
    private String token;
}
```

# 8. 定义控制器

## 8.1 定义登录控制器类

```java
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
```

## 8.2 定义报错处理器

```java
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
```

## 8.3 定义测试控制器

```java
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
```

# 9. 配置类

最后别忘了定义一个配置类，把我们自定义的两个拦截器注册进去。

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new CrossInterceptorHandler()).addPathPatterns(new String[] {"/**"});
        registry.addInterceptor(new LoginInterceptor()).addPathPatterns("/**").excludePathPatterns("/user/login", "/error/**");
    }
}
```

# 10. 最终的效果

访问登录接口，通过提交表单方式提交请求，通过`token`验证后会返回一个`token`，然后我们请求添加了`@Auth`注解的接口都需要在请求头添加`token`字段和对应的值。

<img src="https://image.lukeewin.top/img/202402201744368.png" alt="image-20240220174407236" style="zoom:50%;" />

如果请求头中没有填写`token`或者填写的不对，在请求需求登录后才能访问的接口时都会报错。比如这里的`/test/hello`是需要登录后才能访问的接口，如果没有正确填写`token`，那么会报错，如下图所示。

<img src="https://image.lukeewin.top/img/202402201750721.png" alt="image-20240220175045471" style="zoom:50%;" />

<img src="https://image.lukeewin.top/img/202402201749595.png" alt="image-20240220174939307" style="zoom:50%;" />

如果正确填写了`token`，那么效果如下。

<img src="https://image.lukeewin.top/img/202402201752001.png" alt="image-20240220175214721" style="zoom:50%;" />

有一个`test/hi`接口没有`@Auth`注解，可以不用登录就能访问，如下图所示。

<img src="https://image.lukeewin.top/img/202402201754072.png" alt="image-20240220175428818" style="zoom:50%;" />

以上就是本篇文章所分享的内容，如果对你有用，记得收藏哦！

更多`Java`干货，欢迎关注我的[博客](https://blog.lukeewin.top)。

代码已经开源到`github`中，如需要下载源代码，[可点击这里](https://github.com/lukeewin/jwt-token-demo.git)。
