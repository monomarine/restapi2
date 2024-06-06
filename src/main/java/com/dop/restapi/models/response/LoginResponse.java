package com.dop.restapi.models.response;

import lombok.NoArgsConstructor;
import lombok.Data;
import  lombok.AllArgsConstructor;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    private String email;
    private String password;
}


