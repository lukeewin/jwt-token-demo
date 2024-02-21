package top.lukeewin.jwtdemo.exception;

import com.auth0.jwt.exceptions.TokenExpiredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import top.lukeewin.jwtdemo.utils.R;
import top.lukeewin.jwtdemo.utils.ResponseEnum;

/**
 * @author Luke Ewin
 * @date 2024/2/19 16:27
 * @blog blog.lukeewin.top
 */
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
