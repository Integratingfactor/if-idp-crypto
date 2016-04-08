package com.integratingfactor.idp.crypto.core.service;

import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import com.integratingfactor.idp.crypto.db.service.DaoServerEncryptionService;

@Configuration
@PropertySource("classpath:app-test.properties")
public class IdpServerEncryptionServiceTestConfig {

    @Bean
    @Autowired
    public IdpServerEncryptionService idpServerEncryptionService() {
        return new IdpServerEncryptionService();
    }

    @Bean
    public DaoServerEncryptionService DaoServerEncryptionService() {
        return Mockito.mock(DaoServerEncryptionService.class);
    }

}
