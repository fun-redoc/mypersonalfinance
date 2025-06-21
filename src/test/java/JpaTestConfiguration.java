import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

@TestConfiguration
public class JpaTestConfiguration {

        @Bean
        @Primary
        @ConfigurationProperties("spring.datasource")
        public DataSource dataSource() {
            return DataSourceBuilder.create().build();
        }
}
