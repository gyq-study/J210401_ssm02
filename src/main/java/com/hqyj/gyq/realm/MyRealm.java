package com.hqyj.gyq.realm;

import com.hqyj.gyq.dao.RoleMapper;
import com.hqyj.gyq.dao.UserMapper;
import com.hqyj.gyq.entity.Role;
import com.hqyj.gyq.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MyRealm extends AuthorizingRealm {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private RoleMapper roleMapper;
    /**
     * 授权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //        获取用户名
        String userName = (String) principalCollection.getPrimaryPrincipal();
        User u = userMapper.queryUserByUserName(userName);
        int userId = u.getUserId();
        List<Role> roles = roleMapper.queryRoleByUserId(userId);
//        存放该用户对应角色的名称
        Set<String> roleNames = new HashSet<>();
        for (Role role : roles) {
            roleNames.add(role.getRoleName());
        }
        simpleAuthorizationInfo.addRoles(roleNames);
        return simpleAuthorizationInfo;
    }

    /**
     * 认证
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
            throws AuthenticationException {
// 获取当前登录人的用户名(token是登录凭证)
        String userName = (String) authenticationToken.getPrincipal();
        User user = userMapper.queryUserByUserName(userName);
//        将user放入session
        SecurityUtils.getSubject().getSession().setAttribute("u",user);
        // 该用户不存在
        if (user == null) {
            return null;
        }
        // 获取盐
        ByteSource salt = ByteSource.Util.bytes(userName);
        // 返回认证信息由父类AuthenticatingRealm进行认证
        SimpleAuthenticationInfo simpleAuthenticationInfo =
                new SimpleAuthenticationInfo(userName,user.getUserPassword(),salt,getName());
        return simpleAuthenticationInfo;
    }
}
