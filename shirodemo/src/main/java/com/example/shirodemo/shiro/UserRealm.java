package com.example.shirodemo.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

public class UserRealm extends AuthorizingRealm{
    /**
     * 执行授权逻辑
     * 只要访问了需要权限的资源就会执行授权逻辑
     *
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        //添加资源的授权字符串
        /**
         * 可以通过subject().isPermitted判断用户有没有这个权限再进行授权 ，
         * 判断有没有权限有很多方法，获取用户对象可以用Subject subject = SecurityUtils.getSubject();
         * 不知道是不是这个 看官网又是直接subject().
         */
       /* info.addStringPermission("user:add");

        return info;*/

        return null;
    }

    /**
     * 执行认证逻辑
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //假设数据库的用户名和密码
        String name = "eric";
        String password = "123456";

        //编写shiro判断逻辑，判断用户名和密码
        //1.判断用户名
        UsernamePasswordToken token = (UsernamePasswordToken)authenticationToken;
        if(!token.getUsername().equals(name)){
            //用户名不存在
            return null;//shiro底层会抛出UnKnowAccountException
        }

        //2.判断密码
        return new SimpleAuthenticationInfo("",password,"");

    }
}
