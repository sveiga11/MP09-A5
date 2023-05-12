import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class MainA4 {
    public static void main(String[] args) throws IOException {
        //EXERCICI 1.5
        System.out.println("------------------------------------------------------------------------------");
        System.out.println("1.5. Xifrar i desxifrar un text en clar amb una clau generada amb el codi 1.1.1 \n");

        SecretKey clauSecreta1;

        clauSecreta1 = UtilitatsXifrar.keygenKeyGeneration(128);

        String textXifrat = "Hola soc el Samuel i aquest es l'exercici 1.5 de la Activitat 4 de la UF1!";

        byte[] textEncriptat = UtilitatsXifrar.encryptData(textXifrat.getBytes(), clauSecreta1);
        byte[] textDesencriptat = UtilitatsXifrar.decryptData(textEncriptat, clauSecreta1);

        String fraseDesencriptada1 = new String(textDesencriptat, 0, textDesencriptat.length);
        System.out.println(fraseDesencriptada1);

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.6
        System.out.println("1.6. Xifrar i desxifrar un text en clar amb una clau (codi 1.1.2) generada a partir de la paraula de pas. \n");

        SecretKey clauSecreta2 = UtilitatsXifrar.passwordKeyGeneration("BXJVRFSJZRZR9WE", 192);
        String textXifrat2 = "Hola soc el Samuel i aquest es l'exercici 1.6 de la Activitat 4 de la UF1!";

        byte[] textEncriptat2 = UtilitatsXifrar.encryptData(textXifrat2.getBytes(), clauSecreta2);
        byte[] textDesencriptat2 = UtilitatsXifrar.decryptData(textEncriptat2, clauSecreta2);

        String fraseDesencriptada2 = new String(textDesencriptat2, 0, textDesencriptat2.length);
        System.out.println(fraseDesencriptada2);

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.7
        System.out.println("1.7. Prova alguns dels mètodes que proporciona la classe SecretKey \n");

        SecretKey clauSecreta3 = UtilitatsXifrar.keygenKeyGeneration(256);
        String textXifrat3 = "Hola soc el Samuel i aquest es l'exercici 1.7 de la Activitat 4 de la UF1!";

        byte[] textEncriptat3 = UtilitatsXifrar.encryptData(textXifrat3.getBytes(), clauSecreta3);
        byte[] textDesencriptat3 = UtilitatsXifrar.decryptData(textEncriptat3, clauSecreta3);

        System.out.println(clauSecreta3.getAlgorithm());
        System.out.println(clauSecreta3.getEncoded());
        System.out.println(clauSecreta3.getFormat());

        String fraseDesencriptada3 = new String(textDesencriptat3, 0, textDesencriptat3.length);
        System.out.println(fraseDesencriptada3);

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 1.8
        System.out.println("1.8. Desxifra el text del punt 6 i comprova que donant una paraula de pas incorrecte salta l'excepció BadPaddingException \n");

        SecretKey clauSecreta4 = UtilitatsXifrar.passwordKeyGeneration("SaMuElVF2002", 128);

        byte[] textDesencriptat4 = UtilitatsXifrar.decryptData(textEncriptat2, clauSecreta4);

        String fraseDesencriptada4 = new String(textDesencriptat4, 0, textDesencriptat4.length);
        System.out.println(fraseDesencriptada4);

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");

        //EXERCICI 2
        System.out.println("2. Donat un text xifrat (textamagat) amb algoritme estàndard AES i clau simètrica generada amb el mètode SHA-256 a partir " +
                "d’una contrasenya, i donat un fitxer (clausA4.txt) on hi ha possibles contrasenyes correctes, fes un programa per trobar la bona i " +
                "desxifrar el missatge.\n");

        Path path = Paths.get("textamagat.crypt");
        byte[] textBytes = Files.readAllBytes(path);

        File file = new File("clausA4.txt");
        FileReader fileReader = new FileReader(file);

        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String line = bufferedReader.readLine();

        while(line != null ) {
            SecretKey clauSecreta5 = UtilitatsXifrar.passwordKeyGeneration(line,128);
            byte[] result = UtilitatsXifrar.decryptData(textBytes,clauSecreta5);
            String fraseDesencriptada5 = new String(result,0,result.length);
            System.out.println("lectura: " + fraseDesencriptada5);
            line = bufferedReader.readLine();
        }

        System.out.println();
        System.out.println("------------------------------------------------------------------------------");
    }
}