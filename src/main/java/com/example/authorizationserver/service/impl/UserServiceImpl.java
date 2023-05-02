package com.example.authorizationserver.service.impl;

import com.example.authorizationserver.domain.User;
import com.example.authorizationserver.repository.UserRepository;
import com.example.authorizationserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public Mono<Object> getById(Long id) {
        return userRepository.findById(id).map(userDto -> {
            User user = new User();
            user.setLogin(userDto.getLogin());
            user.setPassword(userDto.getPassword());
            return Mono.just(user);
        });
    }

    @Override
    public Flux<User> getAll() {
        return userRepository.findAll();
    }

    @Override
    public Mono<User> createUser(User user) {
        return userRepository.save(user);
    }
}
