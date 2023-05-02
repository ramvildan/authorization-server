package com.example.authorizationserver.domain;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Data
@Table("usr")
public class User {

    @Id
    @Column("id")
    private Long id;

    @Column("login")
    private String login;

    @Column("password")
    private String password;

}

