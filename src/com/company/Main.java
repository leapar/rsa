package com.company;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import sun.rmi.runtime.Log;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    private static String decode(String license,String E, String N) {
       // BigInteger var2 = new BigInteger("17369712262290647732768133445861332449863405383733306695896586821166245382729380222118948668590047591903813382253186640467063376463309880263824085810383552963627855603429835060435976633955217307266714318344160886538360012623239010786668755679438900124601074924850696725233212494777766999123952653273738958617798460338184668049410136792403729341479373919634041235053823478242208651592611582439749292909499663165109004083820192135244694907138372731716013807836312280426304459316963033144149631900633817073029029413556757588486052978078614048837784810650766996280232645714319416096306667876390555673421669667406990886847");
       // BigInteger var3 = new BigInteger("65537");
        int MAX_ENCRYPT_BLOCK = 256;
        int offSet = 0;
        byte[] cache;
        int i = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {

           /* license = "etUdTQItPKlVrnPBX1A8zcaY+fcUll3Dn8E8yi0SvJ6WUQYzeOULSS6AcYWWQUJmHqIb0Fus4C7mMiOyHwJR5GAlBMSHFaPY04DSsskOQGn6e+T+np36TBGqVni8gGy6tiVAtMZoAI4cvMnhKdBje5O0k8JDYYGTSucF7GG7qEQ=";
            E ="65537";
            N="93404748948314261182510261942864295898258175879892385978035344597790445446504317921638797307057942358993444530477227542470937133210636664882127277394224518895745377444518784380608860269975398795636906397601429785563717386132657879369166968560149045561478169342346120365085034049235188005429804012931375615719";
           */


           E = "65537";
           license="O6cgtIkNkhvTrhfXgyi8xRUEZWYMK9QzjTxQ7SolNgUJA9yNJtAFTEdLXsr8rHhQEk8o5M60zGInTuZUv21J9RhbtnESFvGsJbeqLAyyr9BfeZ7J4ydrB6nk8f3+Iu71BpwLxff1q7cn8Nah3eGBAFboAk56PE3Sn3qmXe3TdTJc2IpyV4otmB9il9+RH8XzJ1iSMMwlDMOtUEfIK5kbG4dhoOBs/2tat1RewXko/kwzzVqLHZj2UD5dbiFxQeJZSJyA4XfOhB1qYXH9eKIQhorD0gYG/sLtKb5EDZVn5umFSxU7mKFblTNEncZpZhm2bgLldteU/AsbKSv7PBCw7gJJkPz6TvNDmHy9mtMzXv4G/pZnFn8q5BjmC/Ql0WgspKVvaOaXcNIC40xRsF0v9df89lheVGenwOVm3dHgrqvFltDyR9GCnlRDuTT3rpoelgcmaLwvU5940F5h0d321TZHXwc5QRYMS7CaTV3Ose7aQ/Byy0tubAdFqoMDEDmDGCjumuUSU3VjkubXHsOuGJWPnkIbvHdv+wrXYru2E3JxB8GecSOAvA8h5hvFHlXuv9LQRUeOfVUeKKq2PnY8/JkqjBSITHyOg18p+RyuU90kDWAze0tIRRQSAVRqhrKolF1VCEi96+jgZEzIqhztAIhFCVaewXqh+CCTqyMt4G5zhzPy94nnvKE6vqmi9D33JmWWJyfwsh6xpYyY2AUopXDS0SYvPr5K+LhrAUTn2DRabO7Gc7+Otl6FaQLvMW1MmVLa/5xCQ0/PrH6hLgVqsZcSSXtcmN7a6+pxUrldSLQGMYoYCbUq+NkhSsTA3gwA+h2Mtx7N/pgnSfTccpc1hRR6RINdlIhZr0TbcZawpFhfNm9J6mzocr2hBkzuPkyyymwjv4CierE9rLlZHm0mIvvnW8QPYigYcDJ1wjbfd1j6FRH/SCl3U5w3h/u76seW9BEVrYUOxtA0xAm3ft7AJq+YbpDP4XnaaLwCxFKsFYMTq++fCEH09kJwzVppSrpO";
            N="17940310759273821186091581584347644044532110653611418699399056760535726181949455909144061033504176046416709472278996844000450948857220538550053615420925570802434732707421445671477723887387914317469612014260650051468786981006855259611418439128933224994326497684896586953029899510145805760405843701781804218344837909274948803595405675987967173096900321030771190203653250898572215814821822532134516026113119288551182967270982365478632519526369244532509171907932412232634363383953554099707402311802908794637876801835946089556255898817291537076439262510079546459483035933240627147365281467516137748986227401106139071070769";

           RSAPublicKeySpec rsaPublicKeySpec = new java.security.spec.RSAPublicKeySpec(new BigInteger(N),new BigInteger(E));

            KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);

            Cipher cipher = javax.crypto.Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            System.out.println("data length:"+license.getBytes(StandardCharsets.UTF_8).length);
            byte[] data = org.apache.commons.codec.binary.Base64.decodeBase64(license.getBytes(StandardCharsets.UTF_8));

            System.out.println("data length:"+data.length);
            int inputLen = data.length;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] datas = out.toByteArray();
            out.close();

           // datas = cipher.doFinal(datas);
            return new String(datas,StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String encode(String license,String D, String N) {
        // BigInteger var2 = new BigInteger("17369712262290647732768133445861332449863405383733306695896586821166245382729380222118948668590047591903813382253186640467063376463309880263824085810383552963627855603429835060435976633955217307266714318344160886538360012623239010786668755679438900124601074924850696725233212494777766999123952653273738958617798460338184668049410136792403729341479373919634041235053823478242208651592611582439749292909499663165109004083820192135244694907138372731716013807836312280426304459316963033144149631900633817073029029413556757588486052978078614048837784810650766996280232645714319416096306667876390555673421669667406990886847");
        // BigInteger var3 = new BigInteger("65537");
        int MAX_ENCRYPT_BLOCK = 128;
        int offSet = 0;
        byte[] cache;
        int i = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            RSAPrivateKeySpec rsaPrivateKeySpec = new java.security.spec.RSAPrivateKeySpec(new BigInteger(N),new BigInteger(D));
            KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);

            Cipher cipher = javax.crypto.Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);

            byte[] data = license.getBytes(StandardCharsets.UTF_8);
            int inputLen = data.length;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] datas = out.toByteArray();
            out.close();

            System.out.println("datas:"+datas.length);

           // byte[] datas = datas = cipher.doFinal(license.getBytes());
            datas = org.apache.commons.codec.binary.Base64.encodeBase64(datas);
            return new String(datas,StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        // write your code here
        KeyPairGenerator keygen = null;
        try {
            keygen = KeyPairGenerator.getInstance("RSA");
            SecureRandom secrand = new SecureRandom();
           // secrand.setSeed("17".getBytes());//初始化随机产生器
            keygen.initialize(2048, secrand);
            KeyPair keys = keygen.genKeyPair();
            PublicKey publicKey = keys.getPublic();
            PrivateKey privateKey = keys.getPrivate();
            String pubKey = Base64.encode(publicKey.getEncoded());
            String priKey = Base64.encode(privateKey.getEncoded());
            System.out.println("pubKey = " + new String(pubKey));
            System.out.println("priKey = " + new String(priKey));

/*
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubkey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
             pubKey = Base64.encode(publicKey.getEncoded());
            System.out.println("pubKey = " + new String(pubKey));
*/

/*
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(prikey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            priKey = Base64.encode(privateKey.getEncoded());
            System.out.println("priKey = " + new String(priKey));
*/
            //(N,e)是公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            System.out.println("RSAPublicKey:");
            System.out.println("Modulus.length=" +
                    rsaPublicKey.getModulus().bitLength());
            System.out.println("Modulus=" + rsaPublicKey.getModulus().toString());//n
            System.out.println("PublicExponent.length=" +
                    rsaPublicKey.getPublicExponent().bitLength());
            System.out.println("PublicExponent=" + rsaPublicKey.getPublicExponent().toString());//e


            //(N,d)是私钥
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            System.out.println("RSAPrivateKey:");
            System.out.println("Modulus.length=" +
                    rsaPrivateKey.getModulus().bitLength());
            System.out.println("Modulus=" + rsaPrivateKey.getModulus().toString());//n
            System.out.println("PrivateExponent.length=" +
                    rsaPrivateKey.getPrivateExponent().bitLength());
            System.out.println("PrivateExponent=" + rsaPrivateKey.getPrivateExponent().toString());//d

            String encodeData = encode("    public static String encode(String toEncode,String D, String N) {\n" +
                    "        // BigInteger var2 = new BigInteger(\"17369712262290647732768133445861332449863405383733306695896586821166245382729380222118948668590047591903813382253186640467063376463309880263824085810383552963627855603429835060435976633955217307266714318344160886538360012623239010786668755679438900124601074924850696725233212494777766999123952653273738958617798460338184668049410136792403729341479373919634041235053823478242208651592611582439749292909499663165109004083820192135244694907138372731716013807836312280426304459316963033144149631900633817073029029413556757588486052978078614048837784810650766996280232645714319416096306667876390555673421669667406990886847\");\n" +
                    "        // BigInteger var3 = new BigInteger(\"65537\");\n" +
                    "        int MAX_ENCRYPT_BLOCK = 128;\n" +
                    "        int offSet = 0;\n" +
                    "        byte[] cache;\n" +
                    "        int i = 0;\n" +
                    "        ByteArrayOutputStream out = new ByteArrayOutputStream();\n" +
                    "        try {\n" +
                    "            RSAPrivateKeySpec rsaPrivateKeySpec = new java.security.spec.RSAPrivateKeySpec(new BigInteger(N),new BigInteger(D));\n" +
                    "            KeyFactory keyFactory = java.security.KeyFactory.getInstance(\"RSA\");\n" +
                    "            PrivateKey privateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);\n" +
                    "            Cipher cipher = javax.crypto.Cipher.getInstance(\"RSA\");\n" +
                    "            cipher.init(Cipher.ENCRYPT_MODE,privateKey);\n" +
                    "\n" +
                    "            byte[] data = toEncode.getBytes(StandardCharsets.UTF_8);\n" +
                    "            int inputLen = data.length;\n" +
                    "            // 对数据分段加密\n" +
                    "            while (inputLen - offSet > 0) {\n" +
                    "                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {\n" +
                    "                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);\n" +
                    "                } else {\n" +
                    "                    cache = cipher.doFinal(data, offSet, inputLen - offSet);\n" +
                    "                }\n" +
                    "                out.write(cache, 0, cache.length);\n" +
                    "                i++;\n" +
                    "                offSet = i * MAX_ENCRYPT_BLOCK;\n" +
                    "            }\n" +
                    "            byte[] datas = out.toByteArray();\n" +
                    "            out.close();\n" +
                    "\n" +
                    "            //byte[] datas = datas = cipher.doFinal(toEncode.getBytes());\n" +
                    "            datas = org.apache.commons.codec.binary.Base64.encodeBase64(datas);\n" +
                    "            return new String(datas,StandardCharsets.UTF_8);\n" +
                    "        } catch (NoSuchAlgorithmException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        } catch (InvalidKeySpecException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        } catch (NoSuchPaddingException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        } catch (InvalidKeyException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        } catch (BadPaddingException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        } catch (IllegalBlockSizeException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        } catch (IOException e) {\n" +
                    "            e.printStackTrace();\n" +
                    "        }\n" +
                    "        return null;\n" +
                    "    }",rsaPrivateKey.getPrivateExponent().toString(),rsaPrivateKey.getModulus().toString());
            String decodeData = decode(encodeData,rsaPublicKey.getPublicExponent().toString(),rsaPublicKey.getModulus().toString());

            System.out.println(encodeData);
            System.out.println(decodeData);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }/* catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }*/
    }



}
