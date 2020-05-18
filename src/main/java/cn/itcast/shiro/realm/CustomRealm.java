package cn.itcast.shiro.realm;

import cn.itcast.shiro.domain.Permission;
import cn.itcast.shiro.domain.Role;
import cn.itcast.shiro.domain.User;
import cn.itcast.shiro.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

/**
 * 自定义的realm,realm的作用是shiro框架做数据库交互的,主要用于对于用户进行认证和鉴权,
 * 认证流程:
 * subject携带用户名和密码给securityManager
 * securityManager将认证工作委托给realm
 * realm调用doGetAuthenticationInfo方法查询数据库认证,并将安全数据存放在session中
 * 鉴权流程:
 * 1.请求经过拦截器拦截
 * 2.通过了拦截器找到方法,如果是注解标注的shiro权限认证则securityManager交给realm
 * 3.realm调用doGetAuthorizationInfo方法,鉴权方法从认证存储的安全数据中获取安全数据进行鉴权.
 */
public class CustomRealm extends AuthorizingRealm {

    public void setName(String name) {
        super.setName("customRealm");
    }

    @Autowired
    private UserService userService;

    /**
     * 授权方法
     *      操作的时候，判断用户是否具有响应的权限
     *          先认证 -- 安全数据
     *          再授权 -- 根据安全数据获取用户具有的所有操作权限
     *
     *
     */
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //1.获取已认证的用户数据
        User user = (User) principalCollection.getPrimaryPrincipal();//得到唯一的安全数据
        //2.根据用户数据获取用户的权限信息（所有角色，所有权限）
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Set<String> roles = new HashSet<>();//所有角色
        Set<String> perms = new HashSet<>();//所有权限
        for (Role role : user.getRoles()) {
            roles.add(role.getName());
            for (Permission perm : role.getPermissions()) {
                perms.add(perm.getCode());
            }
        }
        info.setStringPermissions(perms);
        info.setRoles(roles);
        return info;
    }


    /**
     * 认证方法
     *  参数：传递的用户名密码
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //1.获取登录的用户名密码（token）
        UsernamePasswordToken upToken = (UsernamePasswordToken) authenticationToken;
        String username = upToken.getUsername();
        String password = new String( upToken.getPassword());
        //2.根据用户名查询数据库
        User user = userService.findByName(username);
        //3.判断用户是否存在或者密码是否一致
        if(user != null && user.getPassword().equals(password)) {
            //4.如果一致返回安全数据
            //构造方法：安全数据，密码，realm域名
            SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(user,user.getPassword(),this.getName());
            return info;
        }
        //5.不一致，返回null（抛出异常）
        return null;
    }


    public static void main(String[] args) {
        System.out.println(new Md5Hash("123456","wangwu",3).toString());
    }
}
