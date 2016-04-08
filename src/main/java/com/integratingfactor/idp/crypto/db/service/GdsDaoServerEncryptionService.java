package com.integratingfactor.idp.crypto.db.service;

import java.util.List;
import java.util.logging.Logger;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import com.google.gcloud.datastore.Datastore;
import com.google.gcloud.datastore.DatastoreOptions;
import com.google.gcloud.datastore.KeyFactory;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpWrappedKeySpec;
import com.integratingfactor.idp.common.db.service.GdsDaoBase;
import com.integratingfactor.idp.common.exceptions.db.DbException;

public class GdsDaoServerEncryptionService implements GdsDaoBase, DaoServerEncryptionService, InitializingBean {
    private static Logger LOG = Logger.getLogger(GdsDaoServerEncryptionService.class.getName());

    String serviceNameSpace = null;

    @Autowired
    private Environment env;

    // Create an authorized Datastore service using Application Default
    // Credentials.
    private Datastore datastore;

    // Create a Key factory to construct keys associated with this project.
    private KeyFactory keyFactory;
    // TODO will need a keyfactory of each entity type

    @Override
    public void afterPropertiesSet() throws Exception {
        initialize();
    }

    @Override
    public String nameSpace() {
        return serviceNameSpace;
    }

    @Override
    public void cleanupExpired() {
        // NO OP
    }

    public void initialize() {
        serviceNameSpace = env.getProperty(GdsDaoNameSpaceEnvKey);
        assert (serviceNameSpace != null);
        datastore = DatastoreOptions.builder().namespace(nameSpace()).build().service();
        keyFactory = datastore.newKeyFactory().kind("DaoIdpCrypto");
    }

    @Override
    public IdpEncrypted readVersionedKey(Integer version) throws DbException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<IdpEncrypted> readAllVersionedKeys() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void saveVersionedKey(IdpEncrypted key) throws DbException {
        // TODO Auto-generated method stub

    }

    @Override
    public IdpWrappedKeySpec readWrappedKeySpec(Integer version) throws DbException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<IdpWrappedKeySpec> readAllWrappedKeySpecs() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void saveWrappedKeySpec(IdpWrappedKeySpec keySpec) throws DbException {
        // TODO Auto-generated method stub

    }
}
