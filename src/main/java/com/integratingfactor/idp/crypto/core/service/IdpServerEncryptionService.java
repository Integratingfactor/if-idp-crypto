package com.integratingfactor.idp.crypto.core.service;

import java.io.Serializable;
import java.security.Key;
import java.util.Arrays;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import com.integratingfactor.crypto.lib.factory.model.IdpDecrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpWrappedKeySpec;
import com.integratingfactor.crypto.lib.factory.service.IdpCryptoFactory;
import com.integratingfactor.crypto.lib.factory.specs.IdpPbeKeySpec;
import com.integratingfactor.crypto.lib.factory.specs.IdpSecretKeySpec;
import com.integratingfactor.idp.common.exceptions.db.DbException;
import com.integratingfactor.idp.common.exceptions.db.NotFoundDbException;
import com.integratingfactor.idp.common.exceptions.service.IdpServiceException;
import com.integratingfactor.idp.crypto.db.service.DaoServerEncryptionService;

public class IdpServerEncryptionService implements InitializingBean {

    static final String IdpServerEncryptionAlgorithm = "AES/CBC/PKCS5Padding";

    static final String IdpServerKeyGenerationAlgorithm = "AES";

    static final Integer IdpServerKeyDerivativeCount = 65521;

    static final Integer IdpServerKeyLength = 256;

    private char[] currIdpServerPassPhrase = null;

    private Integer currIdpServerKeyVersion = null;

    private char[] lastIdpServerPassPhrase = null;

    private Integer lastIdpServerKeyVersion = null;

    IdpPbeKeySpec currKeySpec = null;

    IdpPbeKeySpec lastKeySpec = null;

    private ThreadLocal<IdpCryptoFactory> crypto = new ThreadLocal<IdpCryptoFactory>();

    @Autowired
    private Environment env;

    @Autowired
    DaoServerEncryptionService cryptoDao;

    private void initialize() {
        currIdpServerPassPhrase = env.getProperty("idp.service.encryption.pass.phrase.curr").toCharArray();
        assert (currIdpServerPassPhrase != null);
        currIdpServerKeyVersion = Integer.decode(env.getProperty("idp.service.encryption.key.ver.curr"));
        assert (currIdpServerKeyVersion != null);
        String tmpStr = env.getProperty("idp.service.encryption.pass.phrase.last");
        lastIdpServerPassPhrase = tmpStr == null ? null : tmpStr.toCharArray();
        tmpStr = env.getProperty("idp.service.encryption.key.ver.last");
        lastIdpServerKeyVersion = tmpStr == null ? null : Integer.decode(tmpStr);
    }

    public IdpPbeKeySpec getKeySpec(Integer ver, byte[] salt) {
        IdpPbeKeySpec keySpec = new IdpPbeKeySpec();
        keySpec.setEncryptionAlgorithm(IdpServerEncryptionAlgorithm);
        keySpec.setKeyAlgorithm(IdpServerKeyGenerationAlgorithm);
        keySpec.setKeySize(IdpServerKeyLength);
        keySpec.setDerivationCount(IdpServerKeyDerivativeCount);
        keySpec.setSalt(salt);
        keySpec.setVersion(ver);
        return keySpec;
    }

    private void rotateKeySpecs() {
        // check if old version exists in DB
        if (lastKeySpec == null) {
            throw new IdpServiceException("Cannot rotate keys, missing old key information");
        }

        // get factory instances for old and new keys
        IdpCryptoFactory currCrypto = IdpCryptoFactory.getInstance();
        currCrypto.init(currKeySpec, currIdpServerPassPhrase);
        IdpCryptoFactory lastCrypto = IdpCryptoFactory.getInstance();
        lastCrypto.init(lastKeySpec, lastIdpServerPassPhrase);

        // walk through list of pre-existing old keys and re-encrypt with new
        // PBE key
        for (IdpWrappedKeySpec oldKeySpecSe : cryptoDao.readAllWrappedKeySpecs()) {
            // decrypt old key using last key crypto
            IdpSecretKeySpec keySpec = lastCrypto.unwrap(oldKeySpecSe);
            // re-encrypt with new key crypto
            IdpWrappedKeySpec keySpecSe = currCrypto.wrap(keySpec);
            // save re-encrypted key in DB
            saveWrappedKey(keySpecSe);
        }

        // convert last PBE key into secret key definition
        IdpSecretKeySpec keySpec = new IdpSecretKeySpec();
        keySpec.setEncryptionAlgorithm(lastKeySpec.getEncryptionAlgorithm());
        keySpec.setKeyAlgorithm(lastKeySpec.getKeyAlgorithm());
        keySpec.setVersion(lastKeySpec.getVersion());
        keySpec.setKey(Base64Utils.encodeToString(lastCrypto.getKey().getEncoded()));
        // encrypt converted last key using new PBE
        IdpWrappedKeySpec wrappedKeySpec = currCrypto.wrap(keySpec);
        // save re-encrypted key in DB
        saveWrappedKey(wrappedKeySpec);
    }

    private void saveWrappedKey(IdpWrappedKeySpec keySpecSe) {
        try {
            cryptoDao.saveWrappedKeySpec(keySpecSe);
        } catch (DbException e) {
            e.printStackTrace();
            throw new IdpServiceException("Failed to save wrapped key");
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        initialize();
        currKeySpec = getKeySpec(currIdpServerKeyVersion, new String(currIdpServerPassPhrase).getBytes());
        lastIdpServerKeyVersion = currIdpServerKeyVersion - 1;
        if (StringUtils.isEmpty(lastIdpServerPassPhrase)) {
            // there is no last pass phrase, so no rotation applicable
            return;
        }
        lastKeySpec = getKeySpec(lastIdpServerKeyVersion, new String(lastIdpServerPassPhrase).getBytes());
        try {
            // NOTE: can only save keyspec with current PBE, hence checking for
            // versions here.
            // if this check was not in place, then very first key is saved
            // before second key is created, using IV of the first key. and
            // later when trying to decrypt with 2nd key, it fails since IV of
            // 2nd key is different
            if (currIdpServerKeyVersion != lastIdpServerKeyVersion) {
                // read last wrapped key from DB
                cryptoDao.readWrappedKeySpec(lastKeySpec.getVersion());
                // read last versioned key spec
                IdpWrappedKeySpec wrappedKeySpec = cryptoDao.readWrappedKeySpec(lastKeySpec.getVersion());

                // skip rest of below code if executing under test
                if (wrappedKeySpec == null)
                    return;
                // create a new crypto instance
                IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();
                // initialize crypto with last key spec
                crypto.init(lastKeySpec, lastIdpServerPassPhrase);
                // save the generate key
                Key lastKey = crypto.getKey();
                // initializ crypto with wrapped key spec
                crypto.init(crypto.unwrap(wrappedKeySpec));
                // compare keys
                if (!Arrays.equals(crypto.getKey().getEncoded(), lastKey.getEncoded())) {
                    throw new IdpServiceException("wrapped last key is not same as current last key");
                }
            }
        } catch (NotFoundDbException e) {
            // could not read last wrapped key in DB, rotate
            rotateKeySpecs();
        } catch (DbException e) {
            e.printStackTrace();
            throw new IdpServiceException("Error in key rotation check : " + e.getError());
        }
    }

    IdpCryptoFactory myCrypto() {
        IdpCryptoFactory myCrypto = crypto.get();
        if (myCrypto == null) {
            myCrypto = IdpCryptoFactory.getInstance();
            myCrypto.init(currKeySpec, currIdpServerPassPhrase);
            crypto.set(myCrypto);
        }
        return myCrypto;
    }

    public <T extends Serializable> IdpEncrypted encrypt(T data) {
        // run encryption of data
        return myCrypto().encrypt(data);
    }

    private <T extends Serializable> IdpDecrypted<T> decryptWithOldWrappedKeySpec(IdpEncrypted encrypted) {
        try {
            // read old versioned key spec
            IdpWrappedKeySpec wrappedKeySpec = cryptoDao.readWrappedKeySpec(encrypted.getKeyVersion());
            // create a new crypto instance
            IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();
            // initializ crypto with old key spec
            crypto.init(myCrypto().unwrap(wrappedKeySpec));
            // decrypt encrypted data using old keyspec
            return crypto.decrypt(encrypted);
        } catch (DbException | Exception e) {
            e.printStackTrace();
            throw new IdpServiceException("failed to decrypt with wrapped key spec : " + e.getMessage());
        }
    }

    public <T extends Serializable> IdpDecrypted<T> decrypt(IdpEncrypted encrypted) {
        // check if this is encrypted with current version
        if (encrypted.getKeyVersion().equals(currKeySpec.getVersion())) {
            // run decryption of data
            return myCrypto().decrypt(encrypted);
        } else {
            // decrypt using old encryption key
            return decryptWithOldWrappedKeySpec(encrypted);
        }
    }
}
