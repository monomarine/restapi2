package com.dop.restapi.models.response;

import lombok.NoArgsConstructor;
import lombok.Data;
import  lombok.AllArgsConstructor;

import org.springframework.http.HttpStatus;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponse {
    HttpStatus status;
    String message;
}

