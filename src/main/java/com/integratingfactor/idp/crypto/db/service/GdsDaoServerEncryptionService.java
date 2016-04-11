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
import com.integratingfactor.idp.common.db.exceptions.DbException;
import com.integratingfactor.idp.common.db.gds.GdsDaoService;

public class GdsDaoServerEncryptionService implements DaoServerEncryptionService, InitializingBean {
    private static Logger LOG = Logger.getLogger(GdsDaoServerEncryptionService.class.getName());

    @Autowired
    private GdsDaoService gds;


    @Override
    public void afterPropertiesSet() throws Exception {
        // TODO register entity classes with gds service

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
