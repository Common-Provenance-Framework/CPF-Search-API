package cz.muni.xmichalk;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@SecurityScheme(name = "auth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
public class Main {
    public static void main(String[] args) {

        SpringApplication.run(Main.class, args);
    }


}