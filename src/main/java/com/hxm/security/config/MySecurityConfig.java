package com.hxm.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 用户权限控制与角色控制及登录账户
 */
@EnableWebSecurity      //已经带了configuration，不用再加
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 1、定制请求的授权规则
         * permitAll允许所有用户登录
         * hasRole("VIP1")只允许VIP1用户登录的用户进入
         */
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        //开启自动配置登录规则，如果没有登录，没有授权就来到登录页面
        http.formLogin();
        //1.login
        //2.login/error

        http.logout().logoutSuccessUrl("/");

        //开启记住我功能
        http.rememberMe();
        //登录成功后，将cookie发给浏览器保存

    }

//    @Bean
//    @Override
//    public UserDetailsService userDetailsService() {
//        UserDetails user =
//                User.withDefaultPasswordEncoder()
//                        .username("hxm")
//                        .password("123")
//                        .roles("VIP1","VIP2")
//                        .build();
//
//
//        return new InMemoryUserDetailsManager(user);
//    }

    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        auth.inMemoryAuthentication()
                .withUser("zhangsan").password(passwordEncoder().encode("123")).roles("VIP1", "VIP2")
                .and()
                .withUser("lisi").password(passwordEncoder().encode("123")).roles("VIP2", "VIP3")
                .and()
                .withUser("wangwu").password(passwordEncoder().encode("123")).roles("VIP1", "VIP3");

    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
