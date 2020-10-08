package ece443proj1;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	public static void main(String[] args) throws Exception {
	        verifySHA256();
	        System.out.println();
	        perfSHA256();

	        System.out.println();
	        
	        verifySHA512();
	        System.out.println();
	        perfSHA512();
	        
	        System.out.println();

	        verifyAESGCM(false);
	        System.out.println();
	        verifyAESGCM(true);
	        System.out.println();
	        perfAESGCM();
	        
	        System.out.println();
	        
	        verifyAESCBC(false);
	        System.out.println();
	        verifyAESCBC(true);
	        System.out.println();
	        perfAESCBC();
	}
	
	private static String hexString(byte[] buf)
    {
		//This method takes an input buffer that is byte type and converts it to a string value to be printed
		//StringBuilder object creates a string that can be modified by appending, removing, etc. 
        StringBuilder sb = new StringBuilder();
        for (byte b: buf)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }
	
	private static void verifySHA256() throws Exception{
		//method used to verify SHA-256 hash is being used correctly based on known output from given input
		MessageDigest md = MessageDigest.getInstance("SHA-256"); //creating object with SHA-256 as hash algorithm
		
        String str = "Hello world!"; //input string
        String sha256 = "C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A"; //expected hash output
        
        md.update(str.getBytes("UTF-8")); //passing input string
        byte[] hash = md.digest(); //computing hash
        
        System.out.printf("SHA-256 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash));
        System.out.printf("Expected: %s%n", sha256);
	}
	
	private static void perfSHA256() throws Exception{
		//method used to evaluate average performance of SHA-256 hash algorithm
	    int MB = 256; //length of input message in Megabytes
	    int averageFactor = 5; //number of times inner process will be executed to compute the average performance
	    long start[] = new long[averageFactor];
	    long stop[] = new long[averageFactor];
	    byte[] hash = null;
	    long startSum = 0;
	    long stopSum = 0;
	    long averageStart;
	    long averageStop;
	        
	    byte[] buf = new byte[MB*1024*1024];
	    Arrays.fill(buf, (byte)0); //filling input array with all 0's as arbitrary value
	        
	    MessageDigest md = MessageDigest.getInstance("SHA-256"); //creating object with SHA-256 as hash algorithm
	    
	    //calculate the time the process took for specified completions to get average performance
	    for (int i =0; i < start.length; i++) {
		    start[i] = System.currentTimeMillis();
		    md.update(buf); //passing input string
		    hash = md.digest(); //computing hash
		    stop[i] = System.currentTimeMillis();
	    }
	    
	    for (int i =0; i < start.length; i++) {
	    	startSum += start[i];
	    	stopSum += stop[i];
	    }
	    
	    averageStart = startSum/start.length;
	    averageStop = stopSum/stop.length;
	        
	    System.out.printf("SHA-256 of %dMB 0x00%n", MB); //printing number of Megabytes of input
	    System.out.printf("Computed: %s%n", hexString(hash)); //printing output hash as a string
	        
	    System.out.printf("Average time used: %d ms%n", averageStop-averageStart); //calculate and print average time to generate hash output
	    System.out.printf("Average performance: %.2f MB/s%n", MB*1000.0/(averageStop-averageStart)); //calculate and print average MB/s for performance evaluation
	}
	
	private static void verifySHA512() throws Exception{
		//method used to verify SHA-512 hash is being used correctly based on known output from given input
		MessageDigest md = MessageDigest.getInstance("SHA-512"); //creating object with SHA-512 as hash algorithm
        
        String str = "Hello world!"; //input string
        String sha512 = "F6CDE2A0F819314CDDE55FC227D8D7DAE3D28CC556222A0A8AD66D91CCAD4AAD6094F517A2182360C9AACF6A3DC323162CB6FD8CDFFEDB0FE038F55E85FFB5B6"; //expected hash output
        
        md.update(str.getBytes("UTF-8")); //passing input string
        byte[] hash = md.digest(); //computing hash
        
        System.out.printf("SHA-512 of [%s]%n", str); //input string
        System.out.printf("Computed: %s%n", hexString(hash)); //computed hash
        System.out.printf("Expected: %s%n", sha512); //expected value of hash
	}
	
	private static void perfSHA512() throws Exception{
		//method used to evaluate performance of SHA-256 hash algorithm
	    int MB = 256; //length of message in Megabytes
	    int averageFactor = 5; //number of times inner process will be executed to compute the average performance
	    long start[] = new long[averageFactor];
	    long stop[] = new long[averageFactor];
	    byte[] hash = null;
	    long startSum = 0;
	    long stopSum = 0;
	    long averageStart;
	    long averageStop;
	    
	    byte[] buf = new byte[MB*1024*1024];
	    Arrays.fill(buf, (byte)0); //filling input array with all 0's as arbitrary values
	        
	    MessageDigest md = MessageDigest.getInstance("SHA-512"); //creating object with SHA-512 as hash algorithm
	    
	    //calculate the time the process took for specified completions to get average performance
	    for (int i =0; i < start.length; i++) {
		    start[i] = System.currentTimeMillis();
		    md.update(buf); //passing input string
		    hash = md.digest(); //computing hash
		    stop[i] = System.currentTimeMillis();
	    }
	    
	    for (int i =0; i < start.length; i++) {
	    	startSum += start[i];
	    	stopSum += stop[i];
	    }
	    
	    averageStart = startSum/start.length;
	    averageStop = stopSum/stop.length;
	        
	    System.out.printf("SHA-512 of %dMB 0x00%n", MB); //printing number of Megabytes of input
	    System.out.printf("Computed: %s%n", hexString(hash)); //printing output hash as a string
	        
	    System.out.printf("Average time used: %d ms%n", averageStop-averageStart); //calculate and print time to generate hash output
	    System.out.printf("Average performance: %.2f MB/s%n", MB*1000.0/(averageStop-averageStart)); //calculate and print MB/s for performance evaluation
	}
	
	private static void verifyAESGCM(boolean attack) throws Exception {
		//method used to verify AES encryption in GCM mode is being used correctly
		//parameter "attack" set to true if we want to simulate an attack where message is modified in transit from sender to receiver, else false
        String msg = "Hello world!";
        byte[] buf = new byte[1000];
        
        byte[] iv = new byte[12]; //12*8 = 96 bits
        Arrays.fill(iv, (byte)0);
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv); //128 for 128 bit AES, creating IV
        
        byte[] key = new byte[16]; //16*8 = 128 bits
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); //creating AES key

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //setting encryption algorithm

        byte[] plaintext = msg.getBytes("UTF-8");
        
        //len = the number of bytes stored in the buffer
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec); //initialize encryption mode with key and IV generated
        int len = cipher.update(plaintext, 0, plaintext.length, buf); //encrypting the plaintext
        len += cipher.doFinal(buf, len); //MAC being computed and appended
        
        byte[] ciphertext = Arrays.copyOf(buf, len-16); //capturing just the cipher text
        byte[] mac = Arrays.copyOfRange(buf, len-16, len); //capturing just the MAC that was appended to cipher text
        
        System.out.printf("AES/GCM of [%s]%n", msg);
        System.out.printf("Plaintext:  %s%n", hexString(plaintext));
        System.out.printf("Ciphertext: %s%n", hexString(ciphertext));
        System.out.printf("MAC:        %s%n", hexString(mac));
        
        //the below code will change the encrypted cipher text and therefore should not validate the MAC
        if(attack) {
        	//change the first byte in the cipher text to simulate an attacker trying to change message in transit
        	System.out.println("\u001B[36m" + "Simulating attack during transit of message..." + "\u001B[0m");
        	ciphertext[0]++;
        	Thread.sleep(2500);
        }      
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec); //initialize decryption mode with key and IV generated
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf); //decrypting the cipher text to get message back
        len2 += cipher.update(mac, 0, mac.length, buf, len2); //decrypting the mac
        
        boolean verified = true;
        try {
        	len2 += cipher.doFinal(buf, len2); //validating the MAC, will throw BadTagException if MAC is not verified correctly
        }
        catch (javax.crypto.AEADBadTagException e){
        	//if the MAC could not be verified, the message will not be decrypted and will throw a BadTagException
        	verified = false;
        	System.out.printf("\u001B[31m" + "Message could not be authenticated through MAC verification%n");
        	System.out.printf("Decryption will not complete for security reasons...%n" + "\u001B[0m");
        }
        if (verified) {
            byte[] plaintext2 = Arrays.copyOf(buf, len2);
            System.out.printf("Decrypted:  %s%n", hexString(plaintext2));
        }
    }
	
	private static void perfAESGCM() throws Exception {
		//method that evaluates the average performance of AES encryption and decryption in GCM mode
        int MB = 64;
        int averageFactor = 5; //number of times inner process will be executed to compute the average performance
        long startE[] = new long[averageFactor];
	    long stopE[] = new long[averageFactor];
	    long startD[] = new long[averageFactor];
	    long stopD[] = new long[averageFactor];
	    long startESum = 0;
	    long stopESum = 0;
	    long startDSum = 0;
	    long stopDSum = 0;
	    long averageEStart;
	    long averageEStop;
	    long averageDStart;
	    long averageDStop;
	    int len = 0;
	    int len2 = 0;
        
	    byte[] plaintext = new byte[MB*1024*1024];
	    Arrays.fill(plaintext, (byte)0);
	        
	    byte[] buf = new byte[MB*1024*1024+16];
	        
	    for (int i =0; i < startE.length; i++) {
	        byte[] iv = new byte[12];
	        Arrays.fill(iv, (byte)0);
	        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv); //creating IV for AES
	        
	        byte[] key = new byte[16];
	        Arrays.fill(key, (byte)1);
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); //creating key for AES
	
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //setting encryption algorithm
        
	        startE[i] = System.currentTimeMillis();
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
	        len = cipher.update(plaintext, 0, plaintext.length, buf); //encyrpting plain text
	        len += cipher.doFinal(buf, len); //MAC being computed and appended
	        stopE[i] = System.currentTimeMillis();
        
		    byte[] ciphertext = Arrays.copyOf(buf, len-16);
		    byte[] mac = Arrays.copyOfRange(buf, len-16, len);
	        
		    if (i == startE.length-1) {
		        System.out.printf("AES/GCM of %dMB 0x00%n", MB);
		        System.out.printf("Decrypted:  %s[MD5]%n",
		    	        hexString(MessageDigest.getInstance("MD5").digest(plaintext))); //MD-5 hash of input to print shorter string
		        System.out.printf("MAC:        %s%n", hexString(mac));
		    }
       
	        startD[i] = System.currentTimeMillis();
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
	        len2 = cipher.update(ciphertext, 0, ciphertext.length, buf); //decrypt message
	        len2 += cipher.update(mac, 0, mac.length, buf, len2); //decrypt MAC
	        len2 += cipher.doFinal(buf, len2); //validate MAC
	        stopD[i] = System.currentTimeMillis();
        }
        
        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s[MD5]%n",
    	        hexString(MessageDigest.getInstance("MD5").digest(plaintext2))); //MD-5 hash of input to print shorter string
        
        //Find the average times to complete each operation
        for (int i =0; i < startE.length; i++) {
	    	startESum += startE[i];
	    	stopESum += stopE[i];
	    	startDSum += startD[i];
	    	stopDSum += stopD[i];
	    }
        
        averageEStop = stopESum/stopE.length;
        averageEStart = startESum/startE.length;
        averageDStop = stopDSum/stopD.length;
        averageDStart = startDSum/startD.length;
        
        System.out.printf("Average time used: encryption %d ms, decryption %d ms%n", averageEStop-averageEStart, averageDStop-averageDStart); 
        System.out.printf("Average performance: encryption %.2f MB/s, decryption %.2f MB/s%n", MB*1000.0/(averageEStop-averageEStart), MB*1000.0/(averageDStop-averageDStart)); 
    }
	
	private static void verifyAESCBC(boolean attack) throws Exception {
		//attempt at the bonus section
		//method used to verify AES encryption in CBC mode is being used correctly
		//parameter "attack" set to true if we want to simulate an attack where message is modified in transit from sender to receiver, else false
        String msg = "Hello world!";
        byte[] buf = new byte[1000];
        
        byte[] iv = new byte[16]; //16*8 = 128 bits
        Arrays.fill(iv, (byte)0);
        IvParameterSpec ivSpec = new IvParameterSpec(iv); //128 for 128 bit AES, creating IV
        
        byte[] key = new byte[16]; //16*8 = 128 bits
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); //creating AES key

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //setting encryption algorithm

        byte[] plaintext = msg.getBytes("UTF-8");
        
        //len = the number of bytes stored in the buffer
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec); //initialize encryption mode with key and IV generated
        int len = cipher.update(plaintext, 0, plaintext.length, buf); //encrypting the plaintext
        len += cipher.doFinal(buf, len); //finishing encryption
        
        byte[] ciphertext = Arrays.copyOf(buf, len); //capturing just the cipher text
        
        //creating MAC, using encrypt-then MAC method with SHA-256 hash algorithm
        MessageDigest md = MessageDigest.getInstance("SHA-256"); //creating object with SHA-256 as hash algorithm
        md.update(ciphertext); //passing input string
        byte[] hash = md.digest(); //computing hash
        
        System.out.printf("AES/CBC of [%s]%n", msg);
        System.out.printf("Plaintext:  %s%n", hexString(plaintext));
        System.out.printf("Ciphertext: %s%n", hexString(ciphertext));
        System.out.printf("MAC:        %s%n", hexString(hash));
        
        //the below code will change the encrypted cipher text and therefore MAC validation should fail
        if(attack) {
        	//change the first byte in the cipher text to simulate an attacker trying to change message in transit
        	System.out.println("\u001B[36m" + "Simulating attack during transit of message..." + "\u001B[0m");
        	ciphertext[0]++;
        	Thread.sleep(2500);
        }    
       	
    	//verfiying MAC and decrypting
    	md.update(ciphertext); //passing input string y'
        byte[] hash1 = md.digest(); //computing hash h'
        
    	if (!hexString(hash).contentEquals(hexString(hash1))) {
        	System.out.printf("\u001B[31m" + "Message could not be authenticated through MAC verification%n");
        	System.out.printf("Decryption will not complete for security reasons...%n" + "\u001B[0m");
    	}
    	else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec); //initialize decryption mode with key and IV generated
            int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf); //decrypting the cipher text to get message back
        	len2 += cipher.doFinal(buf, len2); //completing decryption
            byte[] plaintext2 = Arrays.copyOf(buf, len2);
            System.out.printf("Decrypted:  %s%n", hexString(plaintext2));
    	}
    }

	private static void perfAESCBC() throws Exception {
		//method that evaluates the average performance of AES encryption and decryption in GCM mode
	    int MB = 64;
	    int averageFactor = 5; //number of times inner process will be executed to compute the average performance
	    long startE[] = new long[averageFactor];
	    long stopE[] = new long[averageFactor];
	    long startD[] = new long[averageFactor];
	    long stopD[] = new long[averageFactor];
	    long startESum = 0;
	    long stopESum = 0;
	    long startDSum = 0;
	    long stopDSum = 0;
	    long averageEStart;
	    long averageEStop;
	    long averageDStart;
	    long averageDStop;
	    int len = 0;
	    int len2 = 0;
	    
	    byte[] plaintext = new byte[MB*1024*1024];
	    Arrays.fill(plaintext, (byte)0);
	        
	    byte[] buf = new byte[MB*1024*1024+16];
	        
	    for (int i =0; i < startE.length; i++) {
	    	byte[] iv = new byte[16]; //16*8 = 128 bits
	        Arrays.fill(iv, (byte)0);
	        IvParameterSpec ivSpec = new IvParameterSpec(iv); //128 for 128 bit AES, creating IV
	        
	        byte[] key = new byte[16];
	        Arrays.fill(key, (byte)1);
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); //creating key for AES
	
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //setting encryption algorithm
	    
	        startE[i] = System.currentTimeMillis();
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
	        len = cipher.update(plaintext, 0, plaintext.length, buf); //encyrpting plain text
	        len += cipher.doFinal(buf, len); //finish encryption
	        //creating MAC, using encrypt-then MAC method
	        MessageDigest md = MessageDigest.getInstance("SHA-256"); //creating object with SHA-256 as hash algorithm
	        md.update(buf); //passing input string
	        byte[] hash = md.digest(); //computing hash
	        stopE[i] = System.currentTimeMillis();
	    
		    byte[] ciphertext = Arrays.copyOf(buf, len);
	        
		    if (i == startE.length-1) {
		        System.out.printf("AES/CBC of %dMB 0x00%n", MB);
		        System.out.printf("Decrypted:  %s[MD5]%n",
		    	        hexString(MessageDigest.getInstance("MD5").digest(plaintext))); //MD-5 hash of input to print shorter string
		        System.out.printf("MAC:        %s%n", hexString(hash));
		    }
		    
		    //verfiying MAC manually and then decrypting
		    startD[i] = System.currentTimeMillis();
	    	md.update(ciphertext); //passing input string y'
	        byte[] hash1 = md.digest(); //computing hash h'
	        
	    	if (!hexString(hash).contentEquals(hexString(hash1))) {
	        	System.out.printf("\u001B[31m" + "Message could not be authenticated through MAC verification%n");
	        	System.out.printf("Decryption will not complete for security reasons...%n" + "\u001B[0m");
	    	}
	    	else {
	    		
		        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		        len2 = cipher.update(ciphertext, 0, ciphertext.length, buf); //decrypt message
		        len2 += cipher.doFinal(buf, len2); //finish decrypting message
	    	}
	        stopD[i] = System.currentTimeMillis();
	    }
	    
	    byte[] plaintext2 = Arrays.copyOf(buf, len2);
	    System.out.printf("Decrypted:  %s[MD5]%n",
	        hexString(MessageDigest.getInstance("MD5").digest(plaintext2))); //MD-5 hash of input to print shorter string
	    
	    //Find the average times to complete each operation
	    for (int i =0; i < startE.length; i++) {
	    	startESum += startE[i];
	    	stopESum += stopE[i];
	    	startDSum += startD[i];
	    	stopDSum += stopD[i];
	    }
	    
	    averageEStop = stopESum/stopE.length;
	    averageEStart = startESum/startE.length;
	    averageDStop = stopDSum/stopD.length;
	    averageDStart = startDSum/startD.length;
	    
	    System.out.printf("Average time used: encryption %d ms, decryption %d ms%n", averageEStop-averageEStart, averageDStop-averageDStart); 
	    System.out.printf("Average performance: encryption %.2f MB/s, decryption %.2f MB/s%n", MB*1000.0/(averageEStop-averageEStart), MB*1000.0/(averageDStop-averageDStart)); 
	}
}


