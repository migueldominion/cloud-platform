package codes.monkey.bootauth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
@ComponentScan({ "codes.monkey.bootauth.task" })
public class SpringTaskConfig {

}
