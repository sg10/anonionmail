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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;

import main.AliasKey;
import main.Mail;
import main.EncryptedRSAkey;
import httpClient.Options;



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
		//testJson();
		//testBase64Converter();
		//printServerKeyAsBase64ForTesting();
		//testPubKeyEncryption();
		//printRequestUserKeyResponseForTesting();
		//printMessagesForFetchRequestForTesting();
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
			//case "-login": logIn(); break;
			case "-exit": System.out.println("Goodbye :) Have a nice day!"); return;
			default: System.out.println("A command error occured :(");
		}
	}

	private void printOptions()
	{
		System.out.println("Command list: ");
		System.out.print( "\t-publicKey\tfor requesting the servers public key (needed for all other commands)\n" +
				//"\t-login\t\tfor logging into the server with alias and password\n"+
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
		//valid |= command.equals("-login");
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
		boolean login_correct = false;
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
		enc_hash = convertToBase64(enc_hash_bytes);
		//encrypting the alias with servers key
		enc_alias_bytes = rsaEncryptData(alias.getBytes(), publicKey_server);
		if(enc_alias_bytes == null)
		{
			System.out.println("Error while encrypting your alias!");
			startClient();
			return;
		}
		enc_alias = convertToBase64(enc_alias_bytes);
		//sending the data to the server
		try
		{
			login_correct = sendLoginRequest(enc_alias, enc_hash);
		}
		catch (IOException e)
		{
			System.out.println("Error while sending the login data to the server!");
			e.printStackTrace();
			return;
		}
		if(login_correct == true)
		{
			//if the server says OK
			identifier = alias;
			System.out.println("Successfully logged in!\n");
		}
		else
		{
			System.out.println("Alias and/or password wrong!");
		}
		startClient();
	}

	private void request_ServerKey()
	{
		System.out.println("Requesting public key from the server...");
		try
		{
			//requesting the key from the server
			publicKey_server = sendServerKeyRequest();
			if(publicKey_server == null)
			{
				System.out.println("Error while requesting public key from the server!");
				startClient();
				return;
			}
			System.out.println("Received public key!\n");
			startClient();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
	
	private PublicKey generateServerPubKey()
	{
		//TODO: only for testing, delete this method if the server connection works
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
		String password;
		String enc_hash;
		EncryptedRSAkey encrypted_key;
		byte[] enc_alias_bytes;
		byte[] pass_hash;
		byte[] enc_hash_bytes;
		boolean is_valid = false;
		boolean result = false;
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
		//encrypt the alias
		enc_alias_bytes = rsaEncryptData(alias.getBytes(), publicKey_server);
		if(enc_alias_bytes == null)
		{
			System.out.println("An unexpected error occured while encrypting your alias!");
			startClient();
			return;
		}
		encrypted_alias = convertToBase64(enc_alias_bytes);
		System.out.println("Please enter your desired password...");
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
		enc_hash = convertToBase64(enc_hash_bytes);
		//encrypt the public key with the servers public key
		encrypted_key = rsaEncryptPublicKey(publicRSAkey, publicKey_server);
		String enc_mod_hex = convertToBase64(encrypted_key.getMod());
		String enc_exp_hex = convertToBase64(encrypted_key.getExp());
		//send the alias, the password and the public key to the server (all encrypted with the servers public key)
		try
		{
			result = sendAliasRequest(encrypted_alias, enc_hash, enc_mod_hex, enc_exp_hex);
		}
		catch (IOException e)
		{
			System.out.println("Error while sending the alias to the server!");
			e.printStackTrace();
			startClient();
			return;
		}
		if(result == true)
		{
			identifier = alias;
			System.out.println("Alias saved!\n");
			startClient();
			return;
		}
		else
		{
			identifier = null;
			System.out.println("Error: The entered alias is not free\n");
			startClient();
		}
	}

	private void request_UserKey(String enc_identifier, String enc_keyowner, String keyowner)
	{
		System.out.println("...requesting the public key from the user...");
		PublicKey user_key;
		try
		{
			user_key = sendUserKeyRequest(enc_identifier, enc_keyowner);
			if(user_key == null)
			{
				System.out.println("Error while requesting the users public key!");
				return;
			}
			//store the new alias-key pair
			AliasKey ak = new AliasKey(keyowner, user_key);
			user_key_list.add(ak);
			System.out.println("Received public key for '" + keyowner + "'!\n");
		}
		catch (IOException e)
		{
			System.out.println("Error while sending user key request!");
			e.printStackTrace();
		}
	}

	private void send_message()
	{
		if(publicKey_server == null)
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		/*if(identifier.isEmpty())
		{
			System.out.println("ERROR: You need an alias before sending a message, so request one if you use the service " +
					"for the first time or log in with your credentials");
			startClient();
			return;
		}*/
		String user_alias = new String();
		String message = new String();
		String answer = new String();
		String encrypted_recipient;
		String encrypted_message;
		String encrypted_aes_key;
		String encrypted_identifier;
		byte[] enc_identifier_bytes;
		byte[] encrypted_alias_bytes;
		byte[] aes_key;
		byte[] encrypted_aes_key_bytes;
		byte[] message_in_bytes;
		byte[] encrypted_message_bytes;
		boolean is_valid = false;
		boolean send_message;
		boolean key_stored;
		PublicKey user_key;
		System.out.println("Sending a message to another user:");
		System.out.println("Please enter your alias...");
		while(is_valid == false)
		{
			identifier = readInput();
			is_valid = checkAlias(identifier);
			if(is_valid == false)
			{
				System.out.println("The given alias is not a valid alias!");
				System.out.println("Please reenter your alias...");
			}
		}
		is_valid = false;
		System.out.println("Please enter the alias of the user you want to send the message to...");
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
		//Encrypt your Identifier with servers public key
		enc_identifier_bytes = rsaEncryptData(identifier.getBytes(), publicKey_server);
		if(enc_identifier_bytes == null)
		{
			System.out.println("Error in encrypting your alias!");
			startClient();
			return;
		}
		encrypted_identifier = convertToBase64(enc_identifier_bytes);
		//Encrypt Recipient with servers public key
		encrypted_alias_bytes = rsaEncryptData(user_alias.getBytes(), publicKey_server);
		if(encrypted_alias_bytes == null)
		{
			System.out.println("Error in encrypting the alias of the recipient!");
			startClient();
			return;
		}
		encrypted_recipient = convertToBase64(encrypted_alias_bytes);
		//check if the public key of this user is already stored in the list of public keys
		key_stored = checkInKeyList(user_alias);
		if(key_stored == false)
		{
			//if not then request it
			request_UserKey(encrypted_identifier, encrypted_recipient, user_alias);
		}
		System.out.println("Please enter the message now...(without linebreaks)");
		message = readInput();
		System.out.println("Do you really want to send '"+ user_alias+"' this message: (yes/no)\n" + "\t" + message);
		answer = readInput();
		send_message = checkAnswer(answer);
		if(send_message == false)
		{
			System.out.println("Sending aborted. Returning to main menu\n");
			startClient();
			return;
		}
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
		encrypted_message = convertToBase64(encrypted_message_bytes);
		//encrypt aes key with recipients public key
		encrypted_aes_key_bytes = rsaEncryptData(aes_key, user_key);
		if(encrypted_aes_key_bytes == null)
		{
			System.out.println("Error in encrypting the AES key");
			startClient();
			return;
		}
		encrypted_aes_key = convertToBase64(encrypted_aes_key_bytes);
		//send message and the key (encrypted with recipient pubkey) to the server together with your id and the recipient (encrypted with servers pubkey)
		try
		{
			send_message = sendSendRequest(encrypted_recipient, encrypted_aes_key, encrypted_identifier, encrypted_message);
			if(send_message == false)
			{
				//Error printed out in the method itself
				//System.out.println("Error while sending your message to the server!");
			}
			else
			{
				System.out.println("Message has been sent!\n");
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
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
		String message;
		String timestamp; //the time field
		String sender; //the from field
		String enc_alias;
		String enc_hash;
		String enc_timestamp; //timestamp from the server
		String enc_sender; //from field from the server
		String enc_aes_key;//aes key from the server
		String enc_message; //message from the server
		byte[] enc_aeskey_bytes; 
		byte[] enc_message_bytes;
		byte[] enc_timestamp_bytes;
		byte[] enc_sender_bytes;
		byte[] sender_bytes;
		byte[] timestamp_bytes;
		byte[] message_bytes;
		byte[] aes_key;
		byte[] enc_alias_bytes;
		byte[] pass_hash;
		byte[] enc_hash_bytes;
		Vector<Mail> mailList = new Vector<Mail>(); //enc mails from the server
		Vector<Mail> dec_mails = new Vector<Mail>(); //dec mails for output
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
		enc_hash = convertToBase64(enc_hash_bytes);
		enc_alias_bytes = rsaEncryptData(identifier.getBytes(), publicKey_server);
		if(enc_alias_bytes == null)
		{
			System.out.println("Error while encrypting your alias!");
			startClient();
			return;
		}
		enc_alias = convertToBase64(enc_alias_bytes);
		//send the fetch request to the server and store the messages in a list
		try
		{
			mailList = sendFetchRequest(enc_alias, enc_hash);
		}
		catch (IOException e)
		{
			System.out.println("Error while retrieving messages from server!");
			e.printStackTrace();
			startClient();
			return;
		}
		message_count = mailList.size();
		for(int i = 0; i < message_count; i++)
		{
			enc_sender = mailList.elementAt(i).getSender_field();
			enc_message = mailList.elementAt(i).getMessage();
			enc_aes_key = mailList.elementAt(i).getAes_key();
			enc_timestamp = mailList.elementAt(i).getTimestamp();
			enc_sender_bytes = convertFromBase64(enc_sender);
			enc_message_bytes = convertFromBase64(enc_message);
			enc_aeskey_bytes = convertFromBase64(enc_aes_key);
			enc_timestamp_bytes = convertFromBase64(enc_timestamp);
			//decrypt the sender
			sender_bytes = rsaDecryptData(enc_sender_bytes, privateRSAkey);
			if(sender_bytes == null)
			{
				System.out.println("Error while decrypting the sender of the message!("+Integer.toString(i+1)+")");
				startClient();
				return;
			}
			sender = new String(sender_bytes);
			//decrypt the timestamp
			timestamp_bytes = rsaDecryptData(enc_timestamp_bytes, privateRSAkey);
			if(timestamp_bytes == null)
			{
				System.out.println("Error while decrypting the timestamp of the message!("+Integer.toString(i+1)+")");
				startClient();
				return;
			}
			timestamp = new String(timestamp_bytes);
			long unixTime = Long.parseLong(timestamp);
			Date d = new Date(unixTime * 1000L);
			String date = d.toString();
			//decrypt the aes key
			aes_key = rsaDecryptData(enc_aeskey_bytes, privateRSAkey);
			if(aes_key == null)
			{
				System.out.println("Error while decrypting the AES key of the message!("+Integer.toString(i+1)+")");
				startClient();
				return;
			}
			//decrypt the message
			message_bytes = aes_crypt(aes_key, enc_message_bytes, false);
			if(message_bytes == null)
			{
				System.out.println("Error while decrypting the message of the message!("+Integer.toString(i+1)+")");
				startClient();
				return;
			}
			message = new String(message_bytes);
			//store the message and the other credentials in the list
			Mail tempMail = new Mail(enc_aes_key, sender, date, message);
			dec_mails.add(tempMail);
		}
		System.out.println("You have " + Integer.toString(message_count) + " new messages: \n");
		//Iterate through the list and print one message at a time, waiting for the user to press enter to show the next one
		for(int i = 0; i < message_count; i++)
		{
			System.out.println(Integer.toString(i+1)+". Message from '" + dec_mails.elementAt(i).getSender_field() + "' - " +
					 dec_mails.elementAt(i).getTimestamp() + ":\n");
			System.out.println("\t" + dec_mails.elementAt(i).getMessage() + "\n");
			System.out.println("Show next message by pressing <Enter>");
			readInput();
		}
		System.out.println("You have no more messages!\n");
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

	private EncryptedRSAkey rsaEncryptPublicKey(PublicKey data, PublicKey key)
	{
		try
		{
			KeyFactory fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(data, RSAPublicKeySpec.class);
			byte[] mod = pub.getModulus().toByteArray();
			byte[] exp = pub.getPublicExponent().toByteArray();
			byte[] mod1 = Arrays.copyOfRange(mod, 0, 200);
			byte[] mod2 = Arrays.copyOfRange(mod, 200, mod.length);
			
			byte[] enc_mod1 = rsaEncryptData(mod1, key);
			byte[] enc_mod2 = rsaEncryptData(mod2, key);
			byte[] enc_exp = rsaEncryptData(exp, key);
			byte[] enc_mod = new byte[enc_mod1.length + enc_mod2.length];
			int length = enc_mod1.length + enc_mod2.length;
			for(int i = 0; i<length; i++)
			{
				if(i < enc_mod1.length)
					enc_mod[i] = enc_mod1[i];
				else
					enc_mod[i] = enc_mod2[i-enc_mod1.length];
			}
			EncryptedRSAkey encKey = new EncryptedRSAkey(enc_mod, enc_exp);
			return encKey;
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("Encryption error: Invalid Algorithm - RSA");
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private PublicKey rsaDecryptPublicKey(EncryptedRSAkey data, PrivateKey key)
	{
		byte[] enc_mod = data.getMod();
		byte[] enc_mod1 = Arrays.copyOfRange(enc_mod, 0, 256);
		byte[] enc_mod2 = Arrays.copyOfRange(enc_mod, 256, enc_mod.length);
		byte[] mod1 = rsaDecryptData(enc_mod1, key);
		byte[] mod2 = rsaDecryptData(enc_mod2, key);
		int length = mod1.length + mod2.length;
		byte[] mod = new byte[length];
		byte[] exp = rsaDecryptData(data.getExp(), key);
		for(int i = 0; i < length; i++)
		{
			if(i < mod1.length)
				mod[i] = mod1[i];
			else
				mod[i] = mod2[i-mod1.length];
		}
		BigInteger modulus = new BigInteger(mod);
		BigInteger exponent = new BigInteger(exp);
	    PublicKey pubKey;
		try
		{
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
			pubKey = fact.generatePublic(keySpec);
			return pubKey;
		}
		catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e)
		{
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

	private String convertToHex(byte[] bytes)
	{
		String hex = Hex.encodeHexString(bytes);
		return hex;
	}

	private byte[] convertFromHex(String hex)
	{
		try
		{
			byte[] bytes = Hex.decodeHex(hex.toCharArray());
			return bytes;
		}
		catch (DecoderException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private String convertToBase64(byte[] bytes)
	{
		String b64 = new BASE64Encoder().encode(bytes);
		return b64;
	}

	private byte[] convertFromBase64(String b64)
	{
		byte[] bytes;
		try
		{
			bytes = new BASE64Decoder().decodeBuffer(b64);
			return bytes;
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	private void testBase64Converter()
	{
		String s = "Frederik war hier";
		byte[] array = s.getBytes();
		System.out.println("Starting string: " + s);
		String b64 = convertToBase64(array);
		System.out.println("Base 64 string: "+b64);
		byte[] new_array = convertFromBase64(b64);
		String newstring = new String(new_array);
		System.out.println("Converted string: " + newstring);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private boolean sendLoginRequest(String enc_alias, String enc_password) throws IOException
	{
		boolean result = false;
		//create the json object
		Map json=new LinkedHashMap();
		String response_body;
		json.put("type","login-request");
		json.put("id",enc_alias);
		json.put("pw",enc_password);
		String jsonText = JSONValue.toJSONString(json);
		System.out.println("Sending request: "+ jsonText); //TODO: remove if all is working
		//send the data to the server
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(Options.SERVER_ADDRESS+Options.REQUEST_LOGIN);
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("JSON", jsonText));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		//get the response
		CloseableHttpResponse response = httpclient.execute(httpPost);
		try
		{
		    System.out.println("Server connection: " + response.getStatusLine() + "\n");
		    HttpEntity entity = response.getEntity();
		    // do something useful with the response body
		    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		    response_body = rd.readLine();
		    if(response_body == null)
		    {
		    	System.out.println("Error: Got no information from the server!");
		    	return result;
		    }
		    Object obj = JSONValue.parse(response_body);
		    JSONObject response_json = (JSONObject) obj;
		    String type;
		    type = (String) response_json.get("type");
		    if(!type.equals("login-response"))
		    {
		    	System.out.println("Error: Got the wrong response from the server!");
		    	return result;
		    }
		    result = (boolean) response_json.get("result");
		    // and ensure it is fully consumed
		    EntityUtils.consume(entity);
		}
		finally
		{
		    response.close();
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private PublicKey sendServerKeyRequest() throws IOException
	{
		//create the json object
		JSONObject json= new JSONObject();
		String response_body;
		String modulus; //to save the modulus of the key
		String exponent; //to save the public exponent
		json.put("type","serverKey-request");
		String jsonText = JSONValue.toJSONString(json);
		System.out.println("Sending request: "+ jsonText); //TODO: remove if all is working
		//send the data to the server
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(Options.SERVER_ADDRESS+Options.REQUEST_SERVER_KEY);
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("JSON", jsonText));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		//get the response
		CloseableHttpResponse response = httpclient.execute(httpPost);
		try
		{
		    System.out.println("Server connection: " + response.getStatusLine() + "\n");
		    HttpEntity entity = response.getEntity();
		    // do something useful with the response body
		    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		    response_body = rd.readLine();
		    if(response_body == null)
		    {
		    	System.out.println("Error: Got no information from the server!");
		    	return null;
		    }
		    Object obj = JSONValue.parse(response_body);
		    JSONObject response_json = (JSONObject) obj;
		    String type;
		    type = (String) response_json.get("type");
		    if(!type.equals("serverKey-response"))
		    {
		    	System.out.println("Error: Got the wrong response from the server!");
		    	return null;
		    }
		    JSONObject pubKey = (JSONObject) response_json.get("pubKey");
		    modulus = (String) pubKey.get("modulus");
		    exponent = (String) pubKey.get("pubExp");
			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		}	
		finally
		{
		    response.close();
		}
		//Recreate the PublicKey Object
		byte[] modu = convertFromBase64(modulus);
		byte[] expo = convertFromBase64(exponent);
		BigInteger mod = new BigInteger(modu);
		BigInteger exp = new BigInteger(expo);
	    PublicKey serverKey;
		try
		{
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
			serverKey = fact.generatePublic(keySpec);
			//System.out.println("Modulus: " + mod.toString(16)); // delete the output, is here just for testing if all worked
			//System.out.println("PublicExponent: " + exp.toString(16));
			return serverKey;
		}
		catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		return null;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private boolean sendAliasRequest(String enc_alias, String enc_password, String enc_modulus, String enc_exponent) throws IOException
	{
		boolean result = false;
		String response_body;
		//create the json object
		Map json=new LinkedHashMap();
		json.put("type","alias-request");
		json.put("id",enc_alias);
		Map json2 = new LinkedHashMap();
		json2.put("modulus", enc_modulus);
		json2.put("pubExp", enc_exponent);
		json.put("pub", json2);
		json.put("pw",enc_password);
		String jsonText = JSONValue.toJSONString(json);
		System.out.println("Sending request: "+ jsonText); //TODO: remove if all is working
		//send the data to the server
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(Options.SERVER_ADDRESS+Options.REQUEST_ALIAS);
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("JSON", jsonText));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		//get the response
		CloseableHttpResponse response = httpclient.execute(httpPost);
		try
		{
		    System.out.println("Server connection: " + response.getStatusLine() + "\n");
		    HttpEntity entity = response.getEntity();
		    // do something useful with the response body
		    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		    response_body = rd.readLine();
		    if(response_body == null)
		    {
		    	System.out.println("Error: Got no information from the server!");
		    	return result;
		    }
		    Object obj = JSONValue.parse(response_body);
		    JSONObject response_json = (JSONObject) obj;
		    String type;
		    type = (String) response_json.get("type");
		    if(!type.equals("alias-response"))
		    {
		    	System.out.println("Error: Got the wrong response from the server!");
		    	return result;
		    }
		    result = (boolean) response_json.get("result");
		    // and ensure it is fully consumed
		    EntityUtils.consume(entity);
		}
		finally
		{
		    response.close();
		}
		return result;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private PublicKey sendUserKeyRequest(String enc_alias, String enc_keyowner) throws IOException
	{
		String enc_key_owner; //the encrypted key owner from the server response
	    String enc_modulus; //the encrypted modulus
	    String enc_exponent;  //the encrypted exponent
		//create the json object
		Map json=new LinkedHashMap();
		json.put("type","public-key-request");
		json.put("id", enc_alias);
		json.put("from", enc_keyowner);
		String jsonText = JSONValue.toJSONString(json);
		String response_body;
		System.out.println("Sending request: "+ jsonText); //TODO: remove if all is working
		//send the data to the server
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(Options.SERVER_ADDRESS+Options.REQUEST_USER_KEY);
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("JSON", jsonText));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		//get the response
		CloseableHttpResponse response = httpclient.execute(httpPost);
		try
		{
		    System.out.println("Server connection: " + response.getStatusLine() + "\n");
		    HttpEntity entity = response.getEntity();
		    // do something useful with the response body
		    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		    response_body = rd.readLine();
		    if(response_body == null)
		    {
		    	System.out.println("Error: Got no information from the server!");
		    	return null;
		    }
		    Object obj = JSONValue.parse(response_body);
		    JSONObject response_json = (JSONObject) obj;
		    String type;
		    type = (String) response_json.get("type");
		    if(!type.equals("public-key-response"))
		    {
		    	System.out.println("Error: Got the wrong response from the server!");
		    	return null;
		    }
		    enc_key_owner = (String) response_json.get("from"); //the encrypted key owner in Base64
		    JSONObject pubKey = (JSONObject) response_json.get("pub");  //the encrypted public key
		    enc_modulus = (String) pubKey.get("modulus"); //the encrypted modulus in Base64
		    enc_exponent = (String) pubKey.get("pubExp");  //the encrypted exponent in Base64
			// and ensure it is fully consumed
			EntityUtils.consume(entity);
		}	
		finally
		{
		    response.close();
		}
		byte[] enc_key_owner_bytes = convertFromBase64(enc_key_owner);
		byte[] key_owner_bytes = rsaDecryptData(enc_key_owner_bytes, privateRSAkey);
		System.out.println("Key Owner: " + new String(key_owner_bytes));
		//got the key encrypted with this users public key - so decrypt it first
		//Recreate the Encrypted Key Object
		byte[] enc_mod = convertFromBase64(enc_modulus);
		byte[] enc_exp = convertFromBase64(enc_exponent);
		EncryptedRSAkey enc_key = new EncryptedRSAkey(enc_mod, enc_exp);
		PublicKey userKey = rsaDecryptPublicKey(enc_key, privateRSAkey);
		//return the decrypted public key
		KeyFactory fact;
		try
		{	//TODO: delete this output if everything is working
			fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(userKey, RSAPublicKeySpec.class);
			byte[] modu = pub.getModulus().toByteArray();
			byte[] expo = pub.getPublicExponent().toByteArray();
			String modu_b64 = convertToBase64(modu);
			String expo_b64 = convertToBase64(expo);
			System.out.println("Modulus: " + modu_b64);
			System.out.println("PublicExponent: " + expo_b64);
		}
		catch (InvalidKeySpecException e)
		{
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		return userKey;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private boolean sendSendRequest(String enc_recipient, String enc_key, String enc_sender, String enc_message) throws IOException
	{
		//send the message
		boolean result = false;
		String response_body;
		//create the json object
		Map json=new LinkedHashMap();
		json.put("type","send-request");
		json.put("to",enc_recipient);
		json.put("key", enc_key);
		json.put("from",enc_sender);
		json.put("msg", enc_message);
		String jsonText = JSONValue.toJSONString(json);
		System.out.println("Sending request: "+ jsonText); //TODO: remove if all is working
		//send the data to the server
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(Options.SERVER_ADDRESS+Options.REQUEST_SEND);
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("JSON", jsonText));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		//get the response
		CloseableHttpResponse response = httpclient.execute(httpPost);
		try
		{
		    System.out.println("Server connection: " + response.getStatusLine() + "\n");
		    HttpEntity entity = response.getEntity();
		    // do something useful with the response body
		    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		    response_body = rd.readLine();
		    if(response_body == null)
		    {
		    	System.out.println("Error: Got no information from the server!");
		    	return result;
		    }
		    Object obj = JSONValue.parse(response_body);
		    JSONObject response_json = (JSONObject) obj;
		    String type;
		    type = (String) response_json.get("type");
		    if(!type.equals("send-response"))
		    {
		    	System.out.println("Error: Got the wrong response from the server!");
		    	return result;
		    }
		    result = (boolean) response_json.get("result");
		    if(result == false)
		    {
		    	String fail_reason = (String) response_json.get("message");
		    	System.out.println("Error while sending the message!");
		    	System.out.println("Errorreason: " + fail_reason);
		    }
		    // and ensure it is fully consumed
		    EntityUtils.consume(entity);
		}
		finally
		{
		    response.close();
		}
		return result;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private Vector<Mail> sendFetchRequest(String enc_identifier, String enc_password) throws IOException
	{
		String enc_key;
		String enc_from;
		String enc_time;
		String enc_message;
		Vector<Mail> mails = new Vector<Mail>();
		//create the json object
		Map json=new LinkedHashMap();
		String response_body;
		json.put("type","fetch-request");
		json.put("to",enc_identifier);
		json.put("pw",enc_password);
		String jsonText = JSONValue.toJSONString(json);
		System.out.println("Sending request: "+ jsonText); //TODO: remove if all is working
		//send the data to the server
		CloseableHttpClient httpclient = HttpClients.createDefault();
		HttpPost httpPost = new HttpPost(Options.SERVER_ADDRESS+Options.REQUEST_MESSAGES);
		List <NameValuePair> nvps = new ArrayList <NameValuePair>();
		nvps.add(new BasicNameValuePair("JSON", jsonText));
		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		//get the response
		CloseableHttpResponse response = httpclient.execute(httpPost);
		try
		{
		    System.out.println("Server connection: " + response.getStatusLine() + "\n");
		    HttpEntity entity = response.getEntity();
		    // do something useful with the response body
		    BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
		    response_body = rd.readLine();
		    if(response_body == null)
		    {
		    	System.out.println("Error: Got no information from the server!");
		    	return null;
		    }
		    Object obj = JSONValue.parse(response_body);
		    JSONObject response_json = (JSONObject) obj;
		    String type;
		    type = (String) response_json.get("type");
		    if(!type.equals("fetch-response"))
		    {
		    	System.out.println("Error: Got the wrong response from the server!");
		    	return null;
		    }
		    //get the array with the messages
			JSONArray array = (JSONArray)response_json.get("messages");
			for(int i = 0; i < array.size(); i++)
			{
				//store each encrypted mail into the vector
				JSONObject jo = (JSONObject)array.get(i);
				enc_key = (String)jo.get("key");
				enc_from = (String)jo.get("from");
				enc_time = (String)jo.get("time");
				enc_message = (String)jo.get("msg");
				Mail mail = new Mail(enc_key, enc_from, enc_time, enc_message);
				mails.add(mail);
			}
		    // and ensure it is fully consumed
		    EntityUtils.consume(entity);
		}
		finally
		{
		    response.close();
		}
		return mails;
	}
	
	@SuppressWarnings("unchecked")
	private void testJson()
	{
		String s;
		Object obj;
		JSONObject obj1;
		JSONObject obj2;
		s = "{\"type\":\"blabla\",\"messages\":[{\"key\":\"hi\",\"from\":\"sepp\"},{\"key\":\"moin\",\"from\":\"klaus\"},{\"key\":\"seas\",\"from\":\"markus\"}" +
				",{\"key\":\"dere\",\"from\":\"fabi\"}]}";
		obj = JSONValue.parse(s);
		obj1 = (JSONObject) obj;
		String type = (String)obj1.get("type");
		JSONArray array = (JSONArray)obj1.get("messages");
		System.out.println("Type: " + type);
		System.out.println("Array Size: " + Integer.toString(array.size()));
		for(int i = 0; i < array.size(); i++)
		{
			JSONObject jo = (JSONObject)array.get(i);
			String key = (String)jo.get("key");
			String from = (String)jo.get("from");
			System.out.println("Key: " + key);
			System.out.println("From: " + from);
		}
		/*s="[0,{\"1\":{\"2\":{\"3\":{\"4\":[5,{\"6\":7}]}}}}]";
		obj=JSONValue.parse(s);
		JSONArray array=(JSONArray)obj;
		System.out.println("======the 2nd element of array======");
		System.out.println(array.get(1));
		System.out.println();
		obj2=(JSONObject)array.get(1); System.out.println("======field \"1\"=========="); System.out.println(obj2.get("1")); */
		/*s="{\"balance\":1000.21,\"num\":100,\"nickname\":null,\"is_vip\":true,\"name\":\"foo\"}";
		obj=JSONValue.parse(s);
		obj2 = (JSONObject)obj;
		System.out.println(obj2.toJSONString());
		System.out.println("Number: " + obj2.get("num"));
		s="[{\"length\":120,\"depth\":10},{\"length\":150,\"depth\":50}]"; obj=JSONValue.parse(s); System.out.println(obj);*/
		/*byte[] key1 = generateAESkey(16);
		String key1_hex = Hex.encodeHexString(key1);
		byte[] key2 = generateAESkey(16);
		String key2_hex = Hex.encodeHexString(key2);
		byte[] from1 = generateAESkey(5);
		String from1_hex = Hex.encodeHexString(from1);
		byte[] from2 = generateAESkey(6);
		String from2_hex = Hex.encodeHexString(from2);
		obj1 = new JSONObject();
		obj1.put("key", key1_hex);
		obj1.put("from", from1_hex);
		obj2 = new JSONObject();
		obj2.put("key", key2_hex);
		obj2.put("from", from2_hex);
		JSONArray list = new JSONArray();
		list.add(obj1);
		list.add(obj2);*/
		//s = list.toJSONString();
		/*JSONObject jobj = new JSONObject();
		jobj.put("type", "fetch-response"); jobj.put("messages", list); System.out.println(jobj);
		Map json=new LinkedHashMap();
		json.put("type","login-request");
		json.put("id",from1_hex);
		json.put("pw",from2_hex);
		String jsonText = JSONValue.toJSONString(json); System.out.println(jsonText);*/
	}
	
	private void testPubKeyEncryption()
	{
		PublicKey tempkey = publicRSAkey;
		printPublicKeyAsBase64ForTesting(tempkey);
		EncryptedRSAkey enc_key = rsaEncryptPublicKey(tempkey, publicRSAkey);
		PublicKey tempkey2 = rsaDecryptPublicKey(enc_key, privateRSAkey);
		printPublicKeyAsBase64ForTesting(tempkey2);
	}

	private void printServerKeyAsBase64ForTesting() //TODO: remove (only for getting a hardcoded hex value of a pubkey for testing server communication)
	{
		PublicKey skey = generateServerPubKey();
		KeyFactory fact;
		try
		{
			fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(skey, RSAPublicKeySpec.class);
			byte[] mod = pub.getModulus().toByteArray();
			byte[] exp = pub.getPublicExponent().toByteArray();
			String mod_hex = convertToBase64(mod);
			String exp_hex = convertToBase64(exp);
			System.out.println("Modulus: " + mod_hex);
			System.out.println("PublicExponent: " + exp_hex);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
	private void printRequestUserKeyResponseForTesting() //TODO: remove (only for getting a hardcoded hex value of a pubkey for testing server communication)
	{
		PublicKey key = generateServerPubKey();
		byte[] alias = "Legolas98".getBytes();
		KeyFactory fact;
		System.out.println("Starting alias: " + convertToBase64(alias));
		EncryptedRSAkey enc_key = rsaEncryptPublicKey(key, publicRSAkey);
		String b64_mod = convertToBase64(enc_key.getMod());
		String b64_exp = convertToBase64(enc_key.getExp());
		System.out.println("Modulus: " + b64_mod);
		System.out.println("PublicExponent: " + b64_exp);
		byte[] enc_alias_bytes = rsaEncryptData(alias, publicRSAkey);
		String b64_alias = convertToBase64(enc_alias_bytes);
		System.out.println("Alias: " + b64_alias);
		System.out.println("---Test---");
		byte[] deb_alias = convertFromBase64(b64_alias);
		byte[] deb_mod = convertFromBase64(b64_mod);
		byte[] deb_exp = convertFromBase64(b64_exp);
		byte[] dec_alias = rsaDecryptData(deb_alias, privateRSAkey);
		EncryptedRSAkey deb_key = new EncryptedRSAkey(deb_mod, deb_exp);
		PublicKey pubb = rsaDecryptPublicKey(deb_key, privateRSAkey);
		try
		{
			fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(pubb, RSAPublicKeySpec.class);
			byte[] mod = pub.getModulus().toByteArray();
			byte[] exp = pub.getPublicExponent().toByteArray();
			String mod_b64 = convertToBase64(mod);
			String exp_b64 = convertToBase64(exp);
			String alias_b64 = convertToBase64(dec_alias);
			System.out.println("Modulus: " + mod_b64);
			System.out.println("PublicExponent: " + exp_b64);
			System.out.println("Alias: " + alias_b64);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
	private void printMessagesForFetchRequestForTesting() //TODO: only for getting some values for the static server...
	{
		Vector<Mail> mails = new Vector<Mail>();
		//1. mail
		long unixTime = System.currentTimeMillis() / 1000L;
		String timestamp = String.valueOf(unixTime);
		String message = "Hi! This is a random message, just for testing the system. Cheers! danny";
		String from = "dannytheBOY";
		byte[] aeskey = generateAESkey(32);
		byte[] enc_message = aes_crypt(aeskey, message.getBytes(), true);
		byte[] enc_key = rsaEncryptData(aeskey, publicRSAkey);
		byte[] enc_time = rsaEncryptData(timestamp.getBytes(), publicRSAkey);
		byte[] enc_from = rsaEncryptData(from.getBytes(), publicRSAkey);
		String enc_msg_b64 = convertToBase64(enc_message);
		String enc_key_b64 = convertToBase64(enc_key);
		String enc_time_b64 = convertToBase64(enc_time);
		String enc_from_b64 = convertToBase64(enc_from);
		Mail m = new Mail(enc_key_b64,enc_from_b64,enc_time_b64,enc_msg_b64);
		mails.add(m);
		//2. mail
		unixTime = 1465490616L;
		timestamp = String.valueOf(unixTime);
		message = "Hello World! How is it going today? :)";
		from = "FunnyProgrammer";
		aeskey = generateAESkey(32);
		enc_message = aes_crypt(aeskey, message.getBytes(), true);
		enc_key = rsaEncryptData(aeskey, publicRSAkey);
		enc_time = rsaEncryptData(timestamp.getBytes(), publicRSAkey);
		enc_from = rsaEncryptData(from.getBytes(), publicRSAkey);
		enc_msg_b64 = convertToBase64(enc_message);
		enc_key_b64 = convertToBase64(enc_key);
		enc_time_b64 = convertToBase64(enc_time);
		enc_from_b64 = convertToBase64(enc_from);
		m = new Mail(enc_key_b64,enc_from_b64,enc_time_b64,enc_msg_b64);
		mails.add(m);
		//3. mail
		unixTime = 1465435311L;
		timestamp = String.valueOf(unixTime);
		message = "What's up! I've got cards for the game next sunday, drop by if you are interested. c-dog";
		from = "charlie";
		aeskey = generateAESkey(32);
		enc_message = aes_crypt(aeskey, message.getBytes(), true);
		enc_key = rsaEncryptData(aeskey, publicRSAkey);
		enc_time = rsaEncryptData(timestamp.getBytes(), publicRSAkey);
		enc_from = rsaEncryptData(from.getBytes(), publicRSAkey);
		enc_msg_b64 = convertToBase64(enc_message);
		enc_key_b64 = convertToBase64(enc_key);
		enc_time_b64 = convertToBase64(enc_time);
		enc_from_b64 = convertToBase64(enc_from);
		m = new Mail(enc_key_b64,enc_from_b64,enc_time_b64,enc_msg_b64);
		mails.add(m);
		//4. mail
		unixTime = 1465402434L;
		timestamp = String.valueOf(unixTime);
		message = "Dear colleagues! I just wanted to remind you all that i'll host a grill party this friday! Hope you're all coming, that would be great fun. cheers fr4nk";
		from = "Fman89";
		aeskey = generateAESkey(32);
		enc_message = aes_crypt(aeskey, message.getBytes(), true);
		enc_key = rsaEncryptData(aeskey, publicRSAkey);
		enc_time = rsaEncryptData(timestamp.getBytes(), publicRSAkey);
		enc_from = rsaEncryptData(from.getBytes(), publicRSAkey);
		enc_msg_b64 = convertToBase64(enc_message);
		enc_key_b64 = convertToBase64(enc_key);
		enc_time_b64 = convertToBase64(enc_time);
		enc_from_b64 = convertToBase64(enc_from);
		m = new Mail(enc_key_b64,enc_from_b64,enc_time_b64,enc_msg_b64);
		mails.add(m);
		//print them :)
		for(int i = 0; i < mails.size(); i++)
		{
			System.out.println("-------" + Integer.toString(i+1) + "-------");
			System.out.println("KEY: " + mails.elementAt(i).getAes_key());
			System.out.println("FROM: " + mails.elementAt(i).getSender_field());
			System.out.println("TIME: " + mails.elementAt(i).getTimestamp());
			System.out.println("MESSAGE: " + mails.elementAt(i).getMessage());
		}
	}
	
	private void printPublicKeyAsBase64ForTesting(PublicKey key) //TODO: remove
	{
		KeyFactory fact;
		try
		{
			fact = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pub = fact.getKeySpec(key, RSAPublicKeySpec.class);
			byte[] mod = pub.getModulus().toByteArray();
			byte[] exp = pub.getPublicExponent().toByteArray();
			String mod_hex = convertToBase64(mod);
			String exp_hex = convertToBase64(exp);
			System.out.println("Modulus: " + mod_hex);
			System.out.println("PublicExponent: " + exp_hex);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
}
