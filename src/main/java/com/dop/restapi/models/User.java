package com.dop.restapi.models;

import lombok.NoArgsConstructor;
import lombok.Data;
import  lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private String email;
    private String name;
    private String password;

    public User(String email, String pass){
        this.email = email;
        this.password=pass;
    }
}
