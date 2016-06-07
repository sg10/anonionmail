package main;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import main.AliasKey;
import main.Mail;



public class Client
{
	private String identifier = new String();
	private Vector<AliasKey> user_key_list;
	private PrivateKey privateRSAkey;
	private PublicKey publicRSAkey;
	private boolean has_keyFile = false;
	private PublicKey publicKey_server;

	public Client()
	{
		user_key_list = new Vector<AliasKey>();
		has_keyFile = checkForFiles();
		if(has_keyFile == false)
		{
			System.out.println("Generating RSA keypair...");
			generateOwnRSAKeys();
		}
		else
		{
			System.out.println("Using stored RSA keypair...");
			readKeysFromFile();
		}
	}

	public void startClient()
	{
		String command = new String();
		boolean valid_command = false;
		while(valid_command == false)
		{
			printOptions();
			command = readInput();
			if(command.equals("ERROR"))
			{
				System.out.println("A reading error occured :(");
			}
			valid_command = checkCommand(command);
			if(valid_command == false)
				System.out.println("ERROR: The given command was wrong! Please choose one command from the list:");
			//System.out.print("Command: " + command + "\n");
		}
		switch(command)
		{
			case "-alias": request_alias(); break;
			case "-fetch": fetch_messages(); break;
			case "-send": send_message(); break;
			case "-publicKey": request_ServerKey(); break;
			case "-login": logIn(); break;
			case "-exit": System.out.println("Goodbye :) Have a nice day!"); return;
			default: System.out.println("A command error occured :(");
		}
	}

	private void printOptions()
	{
		System.out.println("Command list: ");
		System.out.print( "\t-publicKey\tfor requesting the servers public key (needed for all other commands)\n" +
				"\t-login\t\tfor logging into the server with alias and password\n"+
				"\t-alias\t\tfor requesting an new alias\n" +
				"\t-send\t\tfor sending a message to another user\n" +
				"\t-fetch\t\tfor fetching all your mails from the server\n" +
				"\t-exit\t\tfor exiting this application\n\n");
	}

	private String readInput()
	{
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String input_string = "ERROR";
		try
		{
			input_string = br.readLine();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		return input_string;
	}

	private boolean checkCommand(String command)
	{
		boolean valid = false;
		valid |= command.equals("-alias");
		valid |= command.equals("-send");
		valid |= command.equals("-fetch");
		valid |= command.equals("-login");
		valid |= command.equals("-publicKey");
		valid |= command.equals("-exit");
		return valid;
	}

	private boolean checkAlias(String alias)
	{
		int length = alias.length();
		if((length < 5) || (length > 15))
		{
			return false;
		}
		for(int i = 0; i < length; i++)
		{
			char temp = alias.charAt(i);
			int ascii = (int)temp;
			if((ascii < 48) || (ascii > 122))
				return false;
			else if((ascii > 57) && (ascii < 65))
				return false;
			else if((ascii > 90) && (ascii < 97))
				return false;
		}
		return true;
	}

	private boolean checkAnswer(String answer)
	{
		if(answer.equals("yes"))
		{
			return true;
		}
		return false;
	}

	private void logIn()
	{
		if(publicKey_server == null)
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		String alias = new String();
		String password = new String();
		String enc_alias;
		String enc_hash;
		byte[] pass_hash;
		byte[] enc_hash_bytes;
		boolean is_valid = false;
		byte[] enc_alias_bytes;
		System.out.println("Logging in with alias and password:");
		System.out.println("Please enter your alias...");
		while(is_valid == false)
		{
			alias = readInput();
			is_valid = checkAlias(alias);
			if(is_valid == false)
			{
				System.out.println("The given alias is not a valid alias. Please reenter the alias" +
						"(The alias consists of numbers and characters and is between 5 and 15 chars long");
			}
		}
		System.out.println("Please enter your password...");
		password = readInput();
		//hash the password
		pass_hash = createHash(password.getBytes());
		if(pass_hash == null)
		{
			System.out.println("Error while creating the hash of your password");
			startClient();
			return;
		}
		//encrypt the hash
		enc_hash_bytes = rsaEncryptData(pass_hash, publicKey_server);
		if(enc_hash_bytes == null)
		{
			System.out.println("Error while encrypting your password hash!");
			startClient();
			return;
		}
		enc_hash = new String(enc_hash_bytes);
		//encrypting the alias with servers key
		enc_alias_bytes = rsaEncryptData(alias.getBytes(), publicKey_server);
		if(enc_alias_bytes == null)
		{
			System.out.println("Error while encrypting your alias!");
			startClient();
			return;
		}
		enc_alias = new String(enc_alias_bytes);
		//TODO: send the information to the server (encrypted with servers public key)
		identifier = alias; //if the server says OK
		System.out.println("Successfully logged in!");
		startClient();
	}

	private void request_ServerKey()
	{
		System.out.print("Requesting public key from the server...");
		//TODO: connecting to the server and requesting his public key
		publicKey_server = generateServerPubKey(); //TODO: store the actual key...
		System.out.print("OK\n");
		startClient();
	}
	
	private PublicKey generateServerPubKey()
	{
		//TODO: only for testing, delete this method if the server conenction works
		KeyPairGenerator gen;
		PublicKey skey;
		try
		{
			gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair kp = gen.genKeyPair();
			skey = kp.getPublic();
			return skey;
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private void request_alias()
	{
		if(publicKey_server == null)
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		String alias = new String();
		String encrypted_alias;
		String encrypted_key;
		byte[] enc_alias_bytes;
		byte[] enc_key_bytes;
		boolean is_valid = false;
		System.out.println("Requesting Alias:");
		System.out.println("Please enter the alias you want (between 5 and 15 characters and/or numbers)...");
		while(is_valid == false)
		{
			alias = readInput();
			is_valid = checkAlias(alias);
			if(is_valid == false)
			{
				System.out.println("The given alias is not valid. The length has to be between 5 and 15 and only " +
						"character and numbers are allowed!");
			}
		}
		enc_alias_bytes = rsaEncryptData(alias.getBytes(), publicKey_server);
		if(enc_alias_bytes == null)
		{
			System.out.println("An unexpected error occured while encrypting your alias!");
			startClient();
			return;
		}
		encrypted_alias = new String(enc_alias_bytes);
		//enc_key_bytes = rsaEncryptPublicKey(publicRSAkey, publicKey_server);
		enc_key_bytes = rsaEncryptData("this is a key".getBytes(), publicKey_server); //TODO: fix the encrypt public key method ... and then delete this
		if(enc_key_bytes == null)
		{
			System.out.println("An unexpected error occured while encrypting your public key!");
			startClient();
			return;
		}
		encrypted_key = new String(enc_key_bytes);
		//TODO: Send the alias with the public key to the server (both encrypted with servers public key)
		//if the server responds with an ok do:
		identifier = alias;
		System.out.println("Alias saved!\n");
		startClient();
	}

	private void request_UserKey(String user_alias)
	{
		System.out.print("...requesting the public key from the user...");
		//TODO: request the key for the entered alias from the server
		PublicKey user_key = generateServerPubKey(); //TODO: remove the generation; just for testing till the server is rdy
		//store the new alias-key pair
		AliasKey ak = new AliasKey(user_alias, user_key);
		user_key_list.add(ak);
		System.out.print("OK\n");
	}

	private void send_message()
	{
		if(publicKey_server == null)
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		if(identifier.isEmpty())
		{
			System.out.println("ERROR: You need an alias before sending a message, so request one if you use the service " +
					"for the first time or log in with your credentials");
			startClient();
			return;
		}
		System.out.println("Sending a message to another user:");
		System.out.println("Please enter the alias of the user you want to send the message to...");
		String user_alias = new String();
		String message = new String();
		String answer = new String();
		String encrypted_recipient;
		String encrypted_message;
		String encrypted_aes_key;
		byte[] encrypted_alias_bytes;
		byte[] aes_key;
		byte[] encrypted_aes_key_bytes;
		byte[] message_in_bytes;
		byte[] encrypted_message_bytes;
		boolean is_valid = false;
		boolean send_message;
		boolean key_stored;
		PublicKey user_key;
		while(is_valid == false)
		{
			user_alias = readInput();
			is_valid = checkAlias(user_alias);
			if(is_valid == false)
			{
				System.out.println("The given alias is not a valid alias. Other users can only have valid aliases!");
				System.out.println("Please reenter the alias of the user...");
			}
		}
		//check if the public key of this user is already stored in the list of public keys
		key_stored = checkInKeyList(user_alias);
		if(key_stored == false)
		{
			//if not then request it
			request_UserKey(user_alias);
		}
		System.out.println("Please enter the message now...(without linebreaks)");
		message = readInput();
		System.out.println("Do you really want to send '"+ user_alias+"' this message: (yes/no)\n" + message);
		answer = readInput();
		send_message = checkAnswer(answer);
		if(send_message == false)
		{
			System.out.println("Sending aborted. Returning to main menu\n");
			startClient();
			return;
		}
		//Encrypt Recipient with servers public key
		encrypted_alias_bytes = rsaEncryptData(user_alias.getBytes(), publicKey_server);
		if(encrypted_alias_bytes == null)
		{
			System.out.println("Error in encrypting the alias of the recipient!");
			startClient();
			return;
		}
		encrypted_recipient = new String(encrypted_alias_bytes);
		user_key = getKeyOfUser(user_alias); //RSA public key of the user
		if(user_key == null)
		{
			System.out.println("Error in loading the public key from the user!");
			startClient();
			return;
		}
		//encrypt message with aes
		aes_key = generateAESkey(32);
		message_in_bytes = message.getBytes();
		encrypted_message_bytes = aes_crypt(aes_key, message_in_bytes, true);
		if(encrypted_message_bytes == null)
		{
			System.out.println("Error in encrypting the message!");
			startClient();
			return;
		}
		encrypted_message = new String(encrypted_message_bytes);
		//encrypt aes key with recipients public key
		encrypted_aes_key_bytes = rsaEncryptData(aes_key, user_key);
		if(encrypted_aes_key_bytes == null)
		{
			System.out.println("Error in encrypting the AES key");
			startClient();
			return;
		}
		encrypted_aes_key = new String(encrypted_aes_key_bytes);
		//TODO: send message and the key to the server
		System.out.println("Message has been sent!\n");
		startClient();
	}
	
	private boolean checkInKeyList(String searched_alias)
	{
		int length = user_key_list.size();
		for(int i = 0; i < length; i++)
		{
			String temp_alias = user_key_list.elementAt(i).getAlias();
			if(temp_alias.equals(searched_alias))
			{
				return true;
			}
		}
		return false;
	}

	private void fetch_messages()
	{
		if(publicKey_server == null)
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		if(identifier.isEmpty())
		{
			System.out.println("ERROR: You need an alias before sending a message, so request one if you use the service " +
					"for the first time or log in with your credentials");
			startClient();
			return;
		}
		System.out.println("Fetching messages from the server:");
		int message_count = 0;
		String temp_message;
		byte[] aes_key = generateAESkey(32);            //TODO: delete this
		byte[] enc_aeskey = rsaEncryptData(aes_key, publicRSAkey); //TODO: delete the initialization and assign the value from the server
		byte[] enc_message = aes_crypt(aes_key, "Hello World!".getBytes(), true); //TODO: same as above
		String timestamp = "04.04.16 - 12:30"; //the time field //TODO: same as above
		String sender = "Superpeter99"; //the from field   //TODO: same as above
		String enc_alias;
		String enc_hash;
		byte[] enc_alias_bytes;
		byte[] temp_aes_key;
		byte[] temp_message_bytes;
		byte[] pass_hash;
		byte[] enc_hash_bytes;
		Vector<Mail> mailList = new Vector<Mail>();
		System.out.println("Please enter your password...");
		String password = readInput();
		//hash the password
		pass_hash = createHash(password.getBytes());
		if(pass_hash == null)
		{
			System.out.println("Error while creating the hash of your password");
			startClient();
			return;
		}
		//encrypt the hash
		enc_hash_bytes = rsaEncryptData(pass_hash, publicKey_server);
		if(enc_hash_bytes == null)
		{
			System.out.println("Error while encrypting your password hash!");
			startClient();
			return;
		}
		enc_hash = new String(enc_hash_bytes);
		enc_alias_bytes = rsaEncryptData(identifier.getBytes(), publicKey_server);
		if(enc_alias_bytes == null)
		{
			System.out.println("Error while encrypting your alias!");
			startClient();
			return;
		}
		enc_alias = new String(enc_alias_bytes);
		//TODO: send the fetch request to the server and store the messages in a list
		//decrypt the aes key
		temp_aes_key = rsaDecryptData(enc_aeskey, privateRSAkey);
		if(temp_aes_key == null)
		{
			System.out.println("Error while decrypting the AES key!");
			startClient();
			return;
		}
		//decrypt the message
		temp_message_bytes = aes_crypt(temp_aes_key, enc_message, false);
		if(temp_message_bytes == null)
		{
			System.out.println("Error while decrypting the message!");
			startClient();
			return;
		}
		temp_message = new String(temp_message_bytes);
		//store the message and the other credentials in the list
		Mail tempMail = new Mail(new String(temp_aes_key), sender, timestamp, temp_message);
		mailList.add(tempMail);
		System.out.println("You have " + Integer.toString(mailList.size()) + " new messages: \n");
		//TODO: Iterate through the list and print one message at a time, waiting for the user to press enter to show the next one
		for(int i = 0; i < mailList.size(); i++)
		{
			System.out.println("Message from " + mailList.elementAt(i).getSender_field() + " - " + mailList.elementAt(i).getTimestamp() + ":\n");
			System.out.println(mailList.elementAt(i).getMessage() + "\n");
			System.out.println("Show next message by pressing <Enter>");
			readInput();
		}
		System.out.println("You have no more messages!");
		startClient();
	}
	
	private void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws FileNotFoundException, IOException
	{
		ObjectOutputStream out = new ObjectOutputStream(
			    new BufferedOutputStream(new FileOutputStream(fileName)));
		try
		{
			out.writeObject(mod);
			out.writeObject(exp);
		}
		catch (Exception e)
		{
			throw new IOException("Unexpected error while saving to file", e);
		}
		finally
		{
			out.close();
		}
	}

	private void generateOwnRSAKeys()
	{
		try
		{
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair kp = gen.genKeyPair();
			publicRSAkey = kp.getPublic();
			privateRSAkey = kp.getPrivate();
			//saving the key to a file for later uses
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(publicRSAkey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = fact.getKeySpec(privateRSAkey, RSAPrivateKeySpec.class);
			saveToFile("publicRSA.key", pub.getModulus(), pub.getPublicExponent());
			saveToFile("privateRSA.key", priv.getModulus(), priv.getPrivateExponent());
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e)
		{
			System.out.println("Unexpected error while generating RSA keys");
			e.printStackTrace();
		}
	}

	private PublicKey readPublicKeyFromFile(String keyFileName) throws IOException 
	{
		ObjectInputStream in = new ObjectInputStream(
				new BufferedInputStream(new FileInputStream(keyFileName)));
		try
		{
			BigInteger mod = (BigInteger) in.readObject();
		    BigInteger exp = (BigInteger) in.readObject();
		    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PublicKey pubKey = fact.generatePublic(keySpec);
		    return pubKey;
		}
		catch (Exception e)
		{
		    return null;
		}
		finally
		{
		    in.close();
		}
	}

	private PrivateKey readPrivateKeyFromFile(String keyFileName) throws IOException 
	{
		ObjectInputStream in = new ObjectInputStream(
				new BufferedInputStream(new FileInputStream(keyFileName)));
		try
		{
			BigInteger mod = (BigInteger) in.readObject();
		    BigInteger exp = (BigInteger) in.readObject();
		    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(mod, exp);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PrivateKey privKey = fact.generatePrivate(keySpec);
		    return privKey;
		}
		catch (Exception e)
		{
		    return null;
		}
		finally
		{
		    in.close();
		}
	}

	private void readKeysFromFile()
	{
		try
		{
			publicRSAkey = readPublicKeyFromFile("publicRSA.key");
			privateRSAkey = readPrivateKeyFromFile("privateRSA.key");
		}
		catch (IOException e)
		{
			System.out.println("Error while reading key files!");
		}
	}

	private boolean checkForFiles()
	{
		try
		{
			FileInputStream fs1 = new FileInputStream("publicRSA.key");
			FileInputStream fs2 = new FileInputStream("privateRSA.key");
			fs1.close();
			fs2.close();
		}
		catch (IOException e)
		{
			return false;
		}
		return true;
	}

	private PublicKey getKeyOfUser(String user_alias)
	{
		int length = user_key_list.size();
		for(int i = 0; i < length; i++)
		{
			String temp_alias = user_key_list.elementAt(i).getAlias();
			if(temp_alias.equals(user_alias))
			{
				PublicKey userKey = user_key_list.elementAt(i).getPublicKey();
				return userKey;
			}
		}
		return null;
	}

	private byte[] rsaEncryptData(byte[] data, PublicKey key)
	{
		try
		{
			Cipher rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.ENCRYPT_MODE, key);
			byte[] cryptData = rsa.doFinal(data);
			return cryptData;
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("Encryption error: Invalid Algorithm - RSA");
			e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			System.out.println("Encryption error: Invalid Padding - RSA");
			e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - RSA");
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - RSA");
			e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - RSA");
			e.printStackTrace();
		}
		return null;
	}

	private byte[] rsaEncryptPublicKey(PublicKey data, PublicKey key)
	{
		try
		{
			byte[] inputData = data.toString().getBytes();//TODO: change this, so it works...
			Cipher rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.ENCRYPT_MODE, key);
			byte[] cryptData = rsa.doFinal(inputData);
			return cryptData;
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("Encryption error: Invalid Algorithm - RSA");
			e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			System.out.println("Encryption error: Invalid Padding - RSA");
			e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - RSA");
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - RSA");
			e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - RSA");
			e.printStackTrace();
		}
		return null;
	}

	private byte[] rsaDecryptData(byte[] data, PrivateKey key)
	{
		try
		{
			Cipher rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.DECRYPT_MODE, key);
			byte[] cryptData = rsa.doFinal(data);
			return cryptData;
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("Encryption error: Invalid Algorithm - RSA");
			e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			System.out.println("Encryption error: Invalid Padding - RSA");
			e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - RSA");
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - RSA");
			e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - RSA");
			e.printStackTrace();
		}
		return null;
	}

	private byte[] aes_crypt(byte[] key, byte[] data, boolean encrypt)
	{
		try
		{
			byte[] iv = "xx00DEADBEEF00xx".getBytes(); //TODO: maybe randomize the IV and send it with the key to the server
			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			SecretKeySpec k = new SecretKeySpec(key, "AES");
			if(encrypt == true)
			{
				aes.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
			}
			else
			{
				aes.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
			}
			byte[] outputData = aes.doFinal(data);
			return outputData;
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - AES");
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - AES");
			e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - AES");
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private byte[] generateAESkey(int bits)
	{
		byte[] key = new byte[bits];
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(key);
		return key;
	}

	private byte[] createHash(byte[] data)
	{
		try
		{
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			sha.update(data);
			byte[] hash = sha.digest();
			return hash;
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private boolean compareHashes(byte[] hash1, byte[] hash2)
	{
		try
		{
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			return sha.isEqual(hash1, hash2);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		return false;
	}
}
