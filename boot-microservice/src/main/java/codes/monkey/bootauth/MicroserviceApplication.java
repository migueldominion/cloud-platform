package codes.monkey.bootauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 *
 * curl -H "Authorization: Bearer $(curl "client1:@localhost:9999/auth/oauth/token" -d "grant_type=password&username=reader&password=reader" | jq '.access_token' -r)" "http://localhost:9999/resource/foo"
 *
 * curl -H "Authorization: Bearer $(curl "web-app:@localhost:9991/auth/oauth/token" -d "grant_type=password&username=reader&password=reader" | jq '.access_token' -r)" "http://localhost:9992/foo"
 * http://localhost:9999/auth/oauth/authorize?response_type=code&client_id=web-app
 */
@SpringBootApplication
@RestController
class MicroserviceApplication {

    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public Map<String,String> readFoo(@PathVariable Integer id, Principal principal) {
        HashMap<String,String> treeMap = new HashMap<String,String>();
        treeMap.put("id", Integer.toString(id, 0));
        treeMap.put("resource",UUID.randomUUID().toString());
        treeMap.put("user",principal.getName());
                
        return treeMap;
    }


    @Configuration
    @EnableResourceServer
    public static class ResourceServiceConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/**").hasAuthority("READ_PRIVILEGE");
        }

    }

    public static void main(String[] args) {
        SpringApplication.run(MicroserviceApplication.class, args);
    }
}
