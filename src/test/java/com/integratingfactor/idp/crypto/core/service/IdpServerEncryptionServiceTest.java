package com.integratingfactor.idp.crypto.core.service;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.integratingfactor.crypto.lib.factory.model.IdpDecrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpEncrypted;
import com.integratingfactor.crypto.lib.factory.model.IdpWrappedKeySpec;
import com.integratingfactor.crypto.lib.factory.service.IdpCryptoFactory;
import com.integratingfactor.crypto.lib.factory.specs.IdpSecretKeySpec;
import com.integratingfactor.idp.common.db.exceptions.DbException;
import com.integratingfactor.idp.common.db.exceptions.NotFoundDbException;
import com.integratingfactor.idp.crypto.db.service.DaoServerEncryptionService;

@ContextConfiguration(classes = { IdpServerEncryptionServiceTestConfig.class })
public class IdpServerEncryptionServiceTest extends AbstractTestNGSpringContextTests {

    ObjectMapper mapper = new ObjectMapper();

    @Autowired
    IdpServerEncryptionService cryptoService;

    @Autowired
    DaoServerEncryptionService cryptoDao;

    @Autowired
    private Environment env;

    public static String TestPlainText = "*{ a secret }*";

    public static String TestPassPhraseCurr = null;

    public static String TestPassPhraseLast = null;

    public static Integer TestKeyVerCurr = null;

    public static Integer TestKeyVerLast = null;

    @BeforeClass
    public void setup() {
        TestPassPhraseCurr = env.getProperty(IdpServerEncryptionService.IdpServerEncryptionKeyPassPhraseCurr);
        Assert.assertNotNull(TestPassPhraseCurr);
        TestKeyVerCurr = Integer.decode(env.getProperty(IdpServerEncryptionService.IdpServerEncryptionKeyVersionCurr));
        Assert.assertNotNull(TestKeyVerCurr);
        String tmpStr = env.getProperty(IdpServerEncryptionService.IdpServerEncryptionKeyPassPhraseLast);
        TestPassPhraseLast = tmpStr == null ? null : tmpStr;
        tmpStr = env.getProperty(IdpServerEncryptionService.IdpServerEncryptionKeyVersionLast);
        TestKeyVerLast = tmpStr == null ? null : Integer.decode(tmpStr);
    }

    @BeforeMethod
    public void init() {
        // MockitoAnnotations.initMocks(this);
    }

    private String toString(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    @Test
    public void testEncrypt() {
        IdpEncrypted seData = cryptoService.encrypt(TestPlainText);
        System.out.println("Encrypted: " + toString(seData));
        Assert.assertNotNull(seData);
    }

    @Test
    public void testDecrypt() {
        IdpDecrypted<String> data = cryptoService.decrypt(cryptoService.encrypt(TestPlainText));
        System.out.println("Decrypted: " + toString(data));
        Assert.assertEquals(data.getData(), TestPlainText);
    }

    public IdpEncrypted lastVersionedKey() {
        IdpCryptoFactory crypto = IdpCryptoFactory.getInstance();
        crypto.init(cryptoService.getKeySpec(TestKeyVerCurr, TestPassPhraseLast.getBytes()),
                TestPassPhraseLast.toCharArray());
        return crypto.encrypt(crypto.getKey());
    }

    @Test
    public void testRotationWithOldKeyInDb() throws DbException, Exception {
        Mockito.when(cryptoDao.readWrappedKeySpec(TestKeyVerLast)).thenReturn(null);
        cryptoService.afterPropertiesSet();
        Mockito.verify(cryptoDao, Mockito.times(0)).readAllVersionedKeys();
        Mockito.verify(cryptoDao, Mockito.times(0)).saveVersionedKey(Mockito.any(IdpEncrypted.class));
    }

    public static String TestKeyGenerationAlgorithm = "AES";

    public static SecretKey testSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(TestKeyGenerationAlgorithm);
        return keygen.generateKey();
    }

    public static IdpSecretKeySpec testIdpSecretKeySpec(Integer ver)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKey key = testSecretKey();
        IdpSecretKeySpec specs = new IdpSecretKeySpec();
        specs.setEncryptionAlgorithm(IdpServerEncryptionService.IdpServerEncryptionAlgorithm);
        specs.setKeyAlgorithm(key.getAlgorithm());
        specs.setVersion(ver);
        specs.setKey(Base64Utils.encodeToString(key.getEncoded()));
        Assert.assertEquals(key.getEncoded(), Base64Utils.decodeFromString(specs.getKey()));
        return specs;
    }

    public List<IdpEncrypted> oldKeysBeforeVersion(Integer maxVer) throws NoSuchAlgorithmException {
        List<IdpEncrypted> oldKeys = new LinkedList<IdpEncrypted>();
        if (StringUtils.isEmpty(TestPassPhraseLast))
            return oldKeys;
        // create crypto instance using last key specs
        IdpCryptoFactory lastCrypto = IdpCryptoFactory.getInstance();
        lastCrypto.init(cryptoService.lastKeySpec, TestPassPhraseLast.toCharArray());
        for (Integer ver = 1; ver < maxVer; ver++) {
            byte[] keyData = new byte[16];
            new SecureRandom().nextBytes(keyData);
            IdpEncrypted key = lastCrypto.encrypt(testSecretKey());
            key.setKeyVersion(ver);
            oldKeys.add(key);
        }
        return oldKeys;
    }

    public List<IdpWrappedKeySpec> oldWrappedKeySpecsBeforeVersion(Integer maxVer)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        List<IdpWrappedKeySpec> oldKeys = new LinkedList<IdpWrappedKeySpec>();
        if (StringUtils.isEmpty(TestPassPhraseLast))
            return oldKeys;
        // create crypto instance using last key specs
        IdpCryptoFactory lastCrypto = IdpCryptoFactory.getInstance();
        lastCrypto.init(cryptoService.getKeySpec(TestKeyVerLast, TestPassPhraseLast.getBytes()),
                TestPassPhraseLast.toCharArray());

        for (Integer ver = 1; ver < maxVer; ver++) {
            oldKeys.add(lastCrypto.wrap(testIdpSecretKeySpec(ver)));
        }
        return oldKeys;
    }

    // @Test
    public void testRotationWithoutOldKeyInDb() throws DbException, Exception {
        Mockito.when(cryptoDao.readVersionedKey(TestKeyVerLast)).thenThrow(new NotFoundDbException("does not exists"));
        Mockito.when(cryptoDao.readAllVersionedKeys()).thenReturn(oldKeysBeforeVersion(TestKeyVerLast));
        cryptoService.afterPropertiesSet();
        Mockito.verify(cryptoDao, Mockito.times(TestKeyVerCurr - TestKeyVerLast)).readAllVersionedKeys();
        Mockito.verify(cryptoDao, Mockito.times(TestKeyVerCurr - 1)).saveVersionedKey(Mockito.any(IdpEncrypted.class));
    }

    @Test
    public void testRotationWithoutOldWrappedKeyInDb() throws DbException, Exception {
        Mockito.when(cryptoDao.readWrappedKeySpec(TestKeyVerLast))
                .thenThrow(new NotFoundDbException("does not exists"));
        Mockito.when(cryptoDao.readAllWrappedKeySpecs()).thenReturn(oldWrappedKeySpecsBeforeVersion(TestKeyVerLast));
        cryptoService.afterPropertiesSet();
        Mockito.verify(cryptoDao, Mockito.times(TestKeyVerLast == null ? 0 : 1)).readAllWrappedKeySpecs();
        Mockito.verify(cryptoDao, Mockito.times(TestKeyVerLast == null ? 0 : TestKeyVerCurr - 1))
                .saveWrappedKeySpec(Mockito.any(IdpWrappedKeySpec.class));
    }
}
