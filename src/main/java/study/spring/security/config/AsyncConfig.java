package study.spring.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;

@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

	@Override
	@Bean
	public ThreadPoolTaskExecutor getAsyncExecutor() {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(3);
		executor.setMaxPoolSize(5);
		executor.setQueueCapacity(10);
		executor.setThreadNamePrefix("AsyncExecutor");
		executor.initialize();
		return executor;
	}

	@Bean("hello")
	public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
		AsyncTaskExecutor taskExecutor
	) {
		return new DelegatingSecurityContextAsyncTaskExecutor(taskExecutor, SecurityContextHolder.getContext());
	}
}
