package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略静态资源的访问，不进行拦截，提高性能
        web.ignoring().antMatchers("/resources/**");
    }

    // 处理认证。核心组件：AuthenticationManager：认证的核心接口。
    // AuthenticationManagerBuilder 工具类，用来构建AuthenticationManager对象。
    // ProviderManager：AuthenticationManager接口的默认实现类。
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 调用内置的认证规则
        // 底层认证需要UserDetailsService接口，才能根据账号查出user数据，判断账号密码是否正确。
        // passwordEncoder，对密码进行编码的组件。该接口有许多默认实现类。Pbkdf2PasswordEncoder，加密工具，将密码加上salt再进行加密。
        // 我们系统的数据形态不匹配，所以不使用该方法。
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));

        // 自定义认证规则
        // 给AuthenticationManagerBuilder 传入一个组件接口，接口中实现逻辑
        // AuthenticationProvider：ProviderManager持有一组AuthenticationProvider，每个AuthenticationProvider负责一种认证。
        // ProviderManager不自己进行认证，包含一组AuthenticationProvider做认证，为了兼容所有的登录模式e.g.账号密码、微信、指纹、刷脸等等
        // 委托模式：ProviderManager将认证委托给AuthenticationProvider
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication：是用于封装认证信息（账号、密码）的接口，不同的实现类代表不同类型的认证信息。
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                // 认证逻辑
                String username = authentication.getName();
                String password = (String) authentication.getCredentials(); // 得到用户传入的密码

                User user = userService.findUserByName(username);
                if (user == null){
                    throw new UsernameNotFoundException("账号不存在！");// 底层后面由filter捕获异常，统一处理
                }
                password = CommunityUtil.md5(password + user.getSalt());

                if (!user.getPassword().equals(password)){
                    throw new BadCredentialsException("密码不正确！");
                }
                // 返回认证结果，Authentication接口的实例，当前支持的是UsernamePasswordAuthenticationToken类型的实例，所以返回该类型。
                // 三个参数：principal：认证的主要信息，一般为user；credentials：证书，账号密码模式下为密码；authorities：权限
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }
            // 该方法反映当前的AuthenticationProvider支持哪种类型的认证。
            @Override
            public boolean supports(Class<?> aClass) {
                // UsernamePasswordAuthenticationToken：Authentication接口的常用实现类，账号密码认证。
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
            }
        });
    }

    // 处理授权。
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登录相关配置。告诉Security登录页面，登录表单，表单的提交请求，从而拦截该请求，获取账号密码，调用上面的接口，调用认证的逻辑。
        http.formLogin()
                .loginPage("/loginpage") // 登录页面
                .loginProcessingUrl("/login") // 处理登录的请求，从而拦截路径，做认证，调用上面的认证逻辑
//                .successForwardUrl() // 认证成功，跳转路径
//                .failureForwardUrl() // 认证失败，跳转路径。但是不光跳转，往往需要携带数据，这种方式比较局限
                .successHandler(new AuthenticationSuccessHandler() { // 处理器，传入接口，自定义认证成功、失败的逻辑
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        // 认证成功，重定向到首页
                        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/index");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        // 认证失败，回到登录页面，显示错误提示。
                        // 回到登录页面，不能通过重定向方式，因为重定向会让客户端发送新的请求，请求改变，无法向下一个请求传参，只能用跨请求的组件Cookie、Session去传，比较麻烦。
                        // 将参数绑定在request里，把请求转发到登录页面，转发和重定向不同，保持在一个请求之内，可以通过request绑定参数传参
                        // 重定向、转发详见文档。
                        // 当前只能使用转发，不能return模板。因为处于Handler方法内，不是controller内，无法return模板路径。
                        httpServletRequest.setAttribute("error", e.getMessage());
                        httpServletRequest.getRequestDispatcher("/loginpage").forward(httpServletRequest, httpServletResponse);
                    }
                });

        // 退出相关配置
        http.logout()
                .logoutUrl("/logout") // 退出路径
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        // 重定向到首页
                        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/index");
                    }
                });

        // 授权配置。权限与路径的对应关系
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN") // user/admin任一权限，即可访问私信路径
                .antMatchers("/admin").hasAnyAuthority("ADMIN") // admin才能访问admin路径
                .and().exceptionHandling().accessDeniedPage("/denied"); // 如果没登录，不具备任何权限，或者登陆user，没有admin权限，此时不匹配会报错。配置权限不匹配的错误，跳转到错误路径

        // 增加Filter，处理验证码，在账号密码认证filter之前
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                // ServletRequest是父接口，HttpServletRequest是子接口，调用时，传它们的一个实现类，所以可以转型，通常用后者多点，所以此处转型为子接口
                HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                // 只处理登录请求，当前访问路径为/login
                if (httpServletRequest.getServletPath().equals("/login")){
                    String verifyCode = httpServletRequest.getParameter("verifyCode");
                    // 得到验证码之后，判断是否正确。应当提供一个方法专门生成验证码，传到redis和session。此处省略，假设验证码为1234
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")){
                        httpServletRequest.setAttribute("error", "验证码错误！");
                        // 转发，回到登录页面
                        httpServletRequest.getRequestDispatcher("/loginpage").forward(httpServletRequest, httpServletResponse);
                        return;
                    }
                }
                // 如果验证码错误
                // 让请求继续向下执行，走到下一个filter
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        }, UsernamePasswordAuthenticationFilter.class);

        // 记住我
        http.rememberMe()
                .tokenRepository(new InMemoryTokenRepositoryImpl()) // 存储用户数据的方案：存redis，数据库等等。此处存在内存，可自定义实现接口配置
                .tokenValiditySeconds(3600 * 24) // 过期时间，24h
                .userDetailsService(userService); // 这次登录记住，下次再访问，根据凭证从内存中得到userId，根据UserService查询完整信息，方便过认证那一关
    }


}
