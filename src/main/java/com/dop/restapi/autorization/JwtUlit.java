package com.dop.restapi.autorization;
import com.dop.restapi.models.User;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import  org.springframework.security.core.AuthenticationException;
import  org.springframework.stereotype.Component;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUlit {

    private final String key = "anythingstringforsecretkey";    //секретный ключ для шифрования
    private final long tockenChecker = 60*60*1000;              //продолжительность активности токена
    private final String TOKEN_HEADER = "Autorization";         //заголовок токена
    private final String TOKEN_PREFIX = "Bearer ";              //префикс токена
    private final JwtParser parser;     //предназначен для разбора и проверки токенов
    public JwtUlit() {
        //при создании объекта класса парсер инициируется с секретным ключем
        parser = Jwts.parser().setSigningKey((key));
    }
    public String newToken(User user){ //создание токена для пользователя user
        Claims claims = Jwts.claims().setSubject(user.getEmail());
        claims.put("name", user.getName());

        Date tokenCreationDate = new Date();
        Date tokenCheck = new Date((tokenCreationDate.getTime() +
                TimeUnit.MINUTES.toMillis(tockenChecker)));

        return  Jwts.builder()
                .setClaims(claims)
                .setExpiration((tokenCheck))
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
    }

    private Claims readJwtClaims(String token){
        return  parser.parseClaimsJwt(token).getBody();
    }
    public String acceptToken(HttpServletRequest request){ //извлечение токена из заголовка запроса
        String bearerToken = request.getHeader(TOKEN_HEADER);
        if(bearerToken !=null && bearerToken.startsWith(TOKEN_PREFIX)){
            return  bearerToken.substring((TOKEN_PREFIX.length()));
        }
        return  null;
    }
    public Claims acceptClaims(HttpServletRequest request){ //обработка запроса от клиента
        try{
            String token = acceptToken(request);
            if(token!= null){
                return  readJwtClaims(token);
            }
            return  null;
        }
        catch (ExpiredJwtException ex){
            request.setAttribute("Доступ истек", ex.getMessage());
            throw ex;
        }
        catch (Exception ex){
            request.setAttribute("нет доступа", ex.getMessage());
            throw ex;
        }
    }
    public boolean validateClaims(Claims claims) throws  AuthenticationException{ //проверяет действительность утверждений (claims)
        try{
            return  claims.getExpiration().after(new Date());
        }
        catch (Exception ex){
            throw ex;
        }
    }
    public String getEmail(Claims claims){
        return claims.getSubject();
    }
    private List<String> getRoles(Claims claims){
        return (List<String>)  claims.get("roles");
    }
}

