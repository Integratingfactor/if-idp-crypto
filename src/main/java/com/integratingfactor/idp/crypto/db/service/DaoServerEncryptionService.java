package com.integratingfactor.idp.crypto.db.service;

import java.util.List;

import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpWrappedKeySpec;
import com.integratingfactor.idp.common.db.exceptions.DbException;

public interface DaoServerEncryptionService {

    IdpEncrypted readVersionedKey(Integer version) throws DbException;

    List<IdpEncrypted> readAllVersionedKeys();

    void saveVersionedKey(IdpEncrypted key) throws DbException;

    IdpWrappedKeySpec readWrappedKeySpec(Integer version) throws DbException;

    List<IdpWrappedKeySpec> readAllWrappedKeySpecs();

    void saveWrappedKeySpec(IdpWrappedKeySpec keySpec) throws DbException;
}
