package codes.monkey.bootauth.security;

public interface ISecurityUserService {

    String validatePasswordResetToken(long id, String token);

}
