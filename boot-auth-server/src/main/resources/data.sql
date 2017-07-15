INSERT INTO oauth_client_details
	(client_id, client_secret, scope, authorized_grant_types,
	web_server_redirect_uri, authorities, access_token_validity,
	refresh_token_validity, additional_information, autoapprove)
VALUES
	("web-app", "secret", "read,write",
	"implicit,password,authorization_code,refresh_token", "http://localhost:8080/web-app/login", null, 36000, 36000, null, "true"),
	("web-test", "secret", "read,write",
	"implicit,password,authorization_code,refresh_token", "https://www.getpostman.com/oauth2/callback", null, 36000, 36000, null, "true");