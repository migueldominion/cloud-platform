package codes.monkey.bootauth.captcha;

import codes.monkey.bootauth.web.error.ReCaptchaInvalidException;

public interface ICaptchaService {
	void processResponse(final String response) throws ReCaptchaInvalidException;

	String getReCaptchaSite();

	String getReCaptchaSecret();
}
