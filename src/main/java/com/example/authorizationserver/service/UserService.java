package com.example.authorizationserver.service;

import com.example.authorizationserver.domain.User;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface UserService {

    Mono<Object> getById(Long id);

    Flux<User> getAll();

    Mono<User> createUser(User user);
}
