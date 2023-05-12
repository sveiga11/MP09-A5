import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;

public class MainA5 {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        //EXERCICI 1.1.1
        System.out.println("------------------------------------------------------------------------------");
        System.out.println("Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar un missatge.\n");

        KeyPair keys = UtilitatsXifrar.randomGenerate(1024);
        String textXifrat = "1.1.1. Hola soc el Samuel i aquest es l'exercici 1.1.1 de la Activitat 5 de la UF1!";

        byte[] textEncriptat = UtilitatsXifrar.encryptDataA5(textXifrat.getBytes(), keys.getPublic());
        byte[] textDesencriptat = UtilitatsXifrar.decryptDataA5(textEncriptat, keys.getPrivate());

        String fraseDesxifrada = new String(textDesencriptat, 0, textDesencriptat.length);

        System.out.println("Misatge xifrat: " + textEncriptat);
        System.out.println("Misatge desxifrat: " + fraseDesxifrada);

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.1.2
        System.out.println("1.1.2. Fes que el missatge a xifrar s'entra pel teclat.\n");

        KeyPair keys2 = UtilitatsXifrar.randomGenerate(1024);
        System.out.print("Escriu el misatge que vols xifrar: ");
        String textXifrat2 = scanner.nextLine();
        System.out.println();

        byte[] textEncriptat2 = UtilitatsXifrar.encryptDataA5(textXifrat2.getBytes(), keys2.getPublic());
        byte[] textDesencriptat2 = UtilitatsXifrar.decryptDataA5(textEncriptat2, keys2.getPrivate());

        String fraseDesxifrada2 = new String(textDesencriptat2, 0, textDesencriptat2.length);

        System.out.println("Misatge xifrat: " + textEncriptat2);
        System.out.println("Misatge desxifrat: " + fraseDesxifrada2);

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.1.3
        System.out.println("1.1.3. Fes servir els mètodes get Public i getPrivate per obtenir les claus i el mètodes derivats d’aquestes claus i observa quines dades aporten.\n");

        System.out.println("Clau Publica: " + keys.getPublic().getAlgorithm() + " " + Arrays.toString(keys.getPublic().getEncoded()) + " " + keys.getPublic().getFormat());
        System.out.println("Clau Privada " + keys.getPrivate().getAlgorithm() + " " + Arrays.toString(keys.getPrivate().getEncoded()) + " " + keys.getPrivate().getFormat());

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.2.1
        System.out.println("1.2.1. Fés la lectura d’un dels keystore que tinguis al teu sistema i extreu-ne la següent informació: \n");

        KeyStore keyStore = UtilitatsXifrar.loadKeyStore("C:/Users/Samuel Veiga/.keystore","usuario");

        Enumeration<String> enumeration = keyStore.aliases();
        String alias = null;


        System.out.println(
                "1. Tipus de keystore que és (JKS, JCEKS, PKCS12, ...): " + keyStore.getType() + "\n" +
                "2. Mida del magatzem (quantes claus hi ha?): " + keyStore.size() + "\n"

        );

        while (enumeration.hasMoreElements()) {
            alias = enumeration.nextElement();
            System.out.println(
                    "3. Àlies de totes les claus emmagatzemades: " + alias + "\n" +
                    "4. El certificat d’una de les claus: " + keyStore.getCertificate(alias) + "\n\n" +
                    "5. L'algoritme de xifrat d’alguna de les claus: "+ keyStore.getCertificate(alias));
        }

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.2.2
        System.out.println("1.2.2. Crea una nova clau simètrica (SecretKey) i desa-la (setEntry) al keystore. Tingueu en compte que si deseu (mètode store) amb una altra contrasenya el \n" +
                "keystore queda modificat. Fes un captura de pantalla llistant amb la comanda keytool les claus del keystore on has fet la nova entrada.\n");

        SecretKey clauSecreta = UtilitatsXifrar.passwordKeyGeneration("BXJVRFSJZRZR9WE", 192);
        String password = "usuario";

        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(clauSecreta);

        FileOutputStream fileOutputStream = new FileOutputStream("C:/Users/Samuel Veiga/.keystore");
        keyStore.setEntry("mykey2", secretKeyEntry ,protectionParameter);
        keyStore.store(fileOutputStream,password.toCharArray());
        fileOutputStream.close();

        System.out.println("Has desat la teva nova clau a la keystore!!");

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.3
        System.out.println("1.3. Fes un funció que donat un fitxer amb un certificat (.cer) retorni la seva PublicKey. Usa aquesta funció i mostra per pantalla les dades de la PublicKey llegida. \n");

        String rutaFitxer = "C:/Users/Samuel Veiga/Desktop/keytool/miscertificados.cer";
        System.out.println("Ruta del fitxer .cer --> " + rutaFitxer);

        PublicKey publicKey = UtilitatsXifrar.getPublicKey(rutaFitxer);
        System.out.println("Algoritm de la clau publica: " + publicKey.getAlgorithm());
        System.out.println("Format de la clau publica: " + publicKey.getFormat());
        System.out.println("Encoded de la clau publica: " + publicKey.getEncoded());

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        System.out.println("1.4. Llegir una clau asimètrica del keystore i extreure’n la PublicKey. Imprimir-la per pantalla. Podeu crear una funció igual que en el punt 3 fent sobrecàrrega) \n");

        String rutaKeyStore = "C:/Users/Samuel Veiga/Desktop/keytool/keystore_samu.jks";
        System.out.println("Ruta del KeyStore --> " + rutaKeyStore);

        String aliasCertificat = "lamevaclauM9";
        System.out.println("Alias del certificat --> " + aliasCertificat);

        System.out.print("Introdueix el password del Keystore: ");
        String passwordKeyStore = scanner.nextLine();

        System.out.print("Introdueix el password de la Clau: ");
        String passwordClau = scanner.nextLine();

        KeyStore keyStore1 = UtilitatsXifrar.loadKeyStore(rutaKeyStore, passwordKeyStore);
        PublicKey publicKey2 = UtilitatsXifrar.getPublicKey(keyStore1, aliasCertificat, passwordClau);

        System.out.println("Algoritm de la clau publica: " + publicKey2.getAlgorithm());
        System.out.println("Format de la clau publica: " + publicKey2.getFormat());
        System.out.println("Encoded de la clau publica: " + publicKey2.getEncoded());

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.5
        System.out.println("1.5. Fer un funció que donades unes dades i una PrivateKey retorni la signatura. Usa-la i mostra la signatura per pantalla. (funció dels apunts 1.3.1) \n");

        String textXifrat3 = "Hola soc el Samuel i aquest es l'exercici 1.5 de la Activitat 5 de la UF1!";
        byte[] signatura = UtilitatsXifrar.signData(textXifrat3.getBytes(), keys.getPrivate());

        System.out.println("Signatura: " + Arrays.toString(signatura));

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.6
        System.out.println("1.6. Fer una funció que donades unes dades, una signatura i la PublicKey, comprovi la validesa de la informació. (funció dels apunts 1.3.2) \n");


        String textXifrat4 = "Hola soc el Samuel i aquest es l'exercici 1.6 de la Activitat 5 de la UF1!";

        byte[] signatura2 = UtilitatsXifrar.signData(textXifrat3.getBytes(), keys.getPrivate());
        System.out.println( "La validesa de la informació es: " + UtilitatsXifrar.validateSignature(textXifrat4.getBytes(), signatura2, keys.getPublic()));

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 2.2
        System.out.println("2.2. Genereu un parell de claus (KeyPair) i proveu de xifrar i desxifrar un text amb clau embolcallada.\n");

        String textXifrat5 = "Hola soc el Samuel i aquest es l'exercici 2.2 de la Activitat 5 de la UF1!";
        byte[][] textEncriptat3 = UtilitatsXifrar.encryptWrappedData(textXifrat5.getBytes(), keys.getPublic());

        byte[] textDesencriptat3 = UtilitatsXifrar.decryptWrappedData(textEncriptat3, keys.getPrivate());
        String fraseDesencriptada4 = new String(textDesencriptat3,0, textDesencriptat3.length);
        System.out.println(fraseDesencriptada4);


        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

    }
}