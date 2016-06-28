package main;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.Console;
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
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;

import main.AliasKey;
import main.Mail;
import main.EncryptedRSAkey;
import httpClient.Options;



public class Client
{
	private String identifier = new String();
	private String cur_password = new String();
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
		
		System.out.println("Using proxy "+Options.PROXY_ADDRESS);
		request_ServerKey();
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
		}
		switch(command)
		{
			case "a": request_alias(); break;
			case "f": fetch_messages(); break;
			case "s": send_message(); break;
			case "e": System.out.println("Goodbye :) Have a nice day!"); return;
			default: System.out.println("A command error occured :(");
		}
	}

	private void printOptions()
	{
		System.out.println("\n-anONIONmail-");
		if(!identifier.isEmpty())
		{
			System.out.println("Currently identified as '" + identifier + "'.");
		}
		System.out.println("Command list: ");
		System.out.print( "\ta\t--\trequest an new alias\n" +
				"\ts\t--\tsend a message to another user\n" +
				"\tf\t--\tfetch all your mails from the server\n" +
				"\te\t--\texit this application\n\n");
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
			System.out.println("Error while reading your console input!");
			//e.printStackTrace();
		}
		return input_string;
	}
	
	private String readPassword()
	{
		Console console = System.console();
		String input_string = "ERROR";
		if(console == null)
		{
			BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			try
			{
				input_string = br.readLine();
			}
			catch (IOException e)
			{
				//e.printStackTrace();
			}
		}
		else
		{
			char[] pw = console.readPassword();
			input_string = new String(pw);
		}
		return input_string;
	}
	
	private String readMessage()
	{
		String input_string = new String();
		boolean end = false;
		while(end == false)
		{
			String temp = readInput();
			if(temp.length() == 0)
			{
				temp = readInput();
				if(temp.length() == 0)
				{
					end = true;
				}
				else
				{
					input_string = input_string + "\n\t" + temp + "\n\t";
				}
			}
			else
			{
				input_string = input_string + temp + "\n\t";
			}
		}
		return input_string;
	}

	private boolean checkCommand(String command)
	{
		boolean valid = false;
		valid |= command.equals("a");
		valid |= command.equals("s");
		valid |= command.equals("f");
		valid |= command.equals("e");
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
	
	private boolean checkPassword(String pw)
	{
		int length = pw.length();
		if(length < 4)
			return false;
		return true;
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
				return;
			}
			System.out.println("Received public key!\n");
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
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
		String password = new String();
		String password2;
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
		encrypted_alias = DatatypeConverter.printBase64Binary(enc_alias_bytes);
		is_valid = false;
		System.out.println("Please enter your desired password...");
		while(is_valid == false)
		{
			password = readPassword();
			is_valid = checkPassword(password);
			if(is_valid == false)
			{
				System.out.println("The given password is too short. Please insert at least 4 character!");
			}
		}
		System.out.println("Please confirm your password: ");
		password2 = readPassword();
		if(!password.equals(password2))
		{
			System.out.println("Error: The entered passwords do not match!");
			startClient();
			return;
		}
		else
		{
			cur_password = password;
		}
		//hash the password
		pass_hash = createHash(password.getBytes());
		if(pass_hash == null)
		{
			System.out.println("Error while creating the hash of your password");
			startClient();
			return;
		}
		//encrypt the hash
		//System.out.println("password hash "+pass_hash.length+ " : " +new String(pass_hash));
		enc_hash_bytes = rsaEncryptData(pass_hash, publicKey_server);
		if(enc_hash_bytes == null)
		{
			System.out.println("Error while encrypting your password hash!");
			startClient();
			return;
		}
		//System.out.println("password enc " +new String(enc_hash_bytes));
		enc_hash = convertToBase64(enc_hash_bytes);
		//System.out.println("password base64 " +new String(enc_hash));
		//encrypt the public key with the servers public key
		encrypted_key = rsaEncryptPublicKey(publicRSAkey, publicKey_server);
		String enc_mod1_hex = convertToBase64(encrypted_key.getMod1());
		String enc_mod2_hex = convertToBase64(encrypted_key.getMod2());
		String enc_exp_hex = convertToBase64(encrypted_key.getExp());
		//send the alias, the password and the public key to the server (all encrypted with the servers public key)
		try
		{
			result = sendAliasRequest(encrypted_alias, enc_hash, enc_mod1_hex, enc_mod2_hex, enc_exp_hex);
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

	private boolean request_UserKey(String enc_identifier, String enc_keyowner, String keyowner)
	{
		System.out.println("...requesting the public key from the user...");
		PublicKey user_key;
		try
		{
			user_key = sendUserKeyRequest(enc_identifier, enc_keyowner);
			if(user_key == null)
			{
				System.out.println("Error while requesting the users public key!");
				return false;
			}
			//store the new alias-key pair
			AliasKey ak = new AliasKey(keyowner, user_key);
			user_key_list.add(ak);
			System.out.println("Received public key for '" + keyowner + "'!\n");
			return true;
		}
		catch (IOException e)
		{
			System.out.println("Error while sending user key request!");
			//e.printStackTrace();
			return false;
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
		String user_alias = new String();
		String message = new String();
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
		boolean got_key;
		PublicKey user_key;
		System.out.println("Sending a message to another user:");
		if(identifier.isEmpty())
		{
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
		}
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
			got_key = request_UserKey(encrypted_identifier, encrypted_recipient, user_alias);
			if(got_key == false)
			{
				startClient();
				return;
			}
		}
		System.out.println("Please enter the message now...(3 new lines to end)");
		message = readMessage();
		//System.out.println("This is the message:\n" + message);
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
			if(send_message == true)
			{
				System.out.println("Message has been sent!\n");
			}
		}
		catch (IOException e)
		{
			System.out.println("Unexpected error while sending the message to the server!");
			//e.printStackTrace();
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
		System.out.println("Fetching messages from the server:");
		int message_count = 0;
		String message;
		String password;
		String date; //the time field
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
		boolean is_valid = false;
		if(!identifier.isEmpty())
		{
			System.out.println("Using alias '" + identifier + "'...");
		}
		else
		{
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
		}
		if(!cur_password.isEmpty())
		{
			System.out.println("Using stored password...");
			password = cur_password;
		}
		else
		{
			System.out.println("Please enter your password...");
			password = readPassword();
			cur_password = password;
		}
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
			if(mailList == null)
			{
				System.out.println("Received no messages from the server for '" + identifier + "'!");
				startClient();
				return;
			}
		}
		catch (IOException e)
		{
			System.out.println("Error while retrieving messages from server!");
			//e.printStackTrace();
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
			date = new String(timestamp_bytes);
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
			//e.printStackTrace();
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
			//e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			System.out.println("Encryption error: Invalid Padding - RSA");
			//e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - RSA");
			//e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - RSA");
			//e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - RSA");
			//e.printStackTrace();
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
			
			EncryptedRSAkey encKey = new EncryptedRSAkey(enc_mod1, enc_mod2, enc_exp);
			return encKey;
		}
		catch (NoSuchAlgorithmException e)
		{
			System.out.println("Encryption error: Invalid Algorithm - RSA");
			//e.printStackTrace();
		}
		catch (InvalidKeySpecException e)
		{
			//e.printStackTrace();
		}
		return null;
	}

	private PublicKey rsaDecryptPublicKey(EncryptedRSAkey data, PrivateKey key)
	{
		byte[] enc_mod1 = data.getMod1();
		byte[] enc_mod2 = data.getMod2();
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
			//e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e)
		{
			//e.printStackTrace();
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
			//e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			System.out.println("Encryption error: Invalid Padding - RSA");
			//e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - RSA");
			//e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - RSA");
			//e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - RSA");
			//e.printStackTrace();
		}
		return null;
	}

	private byte[] aes_crypt(byte[] key, byte[] data, boolean encrypt)
	{
		try
		{
			byte[] iv = "xx00DEADBEEF00xx".getBytes(); //maybe randomize the IV and send it with the key to the server
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
			//e.printStackTrace();
		}
		catch (NoSuchPaddingException e)
		{
			//e.printStackTrace();
		}
		catch (InvalidKeyException e)
		{
			System.out.println("Encryption error: Invalid key - AES");
			//e.printStackTrace();
		}
		catch (IllegalBlockSizeException e)
		{
			System.out.println("Encryption error: Invalid block size - AES");
			//e.printStackTrace();
		}
		catch (BadPaddingException e)
		{
			System.out.println("Encryption error: Bad Padding - AES");
			//e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e)
		{
			//e.printStackTrace();
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
			System.out.println("Unexpected error while hashing!");
			//e.printStackTrace();
		}
		return null;
	}

	private String convertToBase64(byte[] bytes)
	{
		String b64 = DatatypeConverter.printBase64Binary(bytes);
		return b64;
	}

	private byte[] convertFromBase64(String b64)
	{
		byte[] bytes = DatatypeConverter.parseBase64Binary(b64);
		return bytes;
	}
	
	private JSONObject sendToServer(String json){

		//System.out.println("Sending request: "+ json);
		//send the data to the server
		CloseableHttpResponse response = null;
		JSONObject response_json = null;
		boolean connected = false;
		int tries = 0;
		while((connected == false) && (tries < 15))
		{
			try
			{   
				connected = true;
				CloseableHttpClient httpclient = HttpClients.createDefault();
				HttpPost httpPost = new HttpPost(Options.PROXY_ADDRESS);
				httpPost.setHeader("Host", Options.SERVER_ADDRESS);
				StringEntity sentity = new StringEntity(json);
				sentity.setContentType(new BasicHeader("Content-Type",
						"application/json"));
				httpPost.setEntity(sentity);
				//get the response
				response = httpclient.execute(httpPost);
				String response_body;
				//System.out.println("Server connection: " + response.getStatusLine() + "\n");
				HttpEntity entity = response.getEntity();
				// do something useful with the response body
				BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
				response_body = rd.readLine();
				if(response_body == null)
				{
					System.out.println("Error: Got no information from the server!");
					return null;
				}
				//System.out.println(response_body);
				Object obj = JSONValue.parse(response_body);
				response_json = (JSONObject) obj;
				// and ensure it is fully consumed
				EntityUtils.consume(entity);
			}
			catch (Exception e){
				connected = false;
				tries++;
				System.out.println("Error while connecting to server. Retrying..." + Integer.toString(tries));
				try {
					Thread.sleep(2000);
				} catch (InterruptedException e1) {
					//e1.printStackTrace();
				}
				//e.printStackTrace();
			}
			finally
			{
				try {
					if(response!=null) response.close();
				} catch (IOException e) {
				}
			}
		}
		return response_json;
	}

	@SuppressWarnings("unchecked")
	private PublicKey sendServerKeyRequest() throws IOException
	{
		//create the json object
		JSONObject json= new JSONObject();
		String modulus; //to save the modulus of the key
		String exponent; //to save the public exponent
		json.put("type","serverKey-request");
		
		String jsonText = JSONValue.toJSONString(json);
		
		JSONObject response_json = sendToServer(jsonText);
		if(response_json==null){
			System.out.println("Error: Could not parse JSON from server!");
			return null;
		}
	    String type;
	    type = (String) response_json.get("type");
	    if(!type.equals("serverKey-response"))
	    {
	    	//System.out.println("Error: Got the wrong response from the server!");
	    	return null;
	    }
	    JSONObject pubKey = (JSONObject) response_json.get("pubKey");
	    modulus = (String) pubKey.get("modulus");
	    exponent = (String) pubKey.get("pubExp");
			
			
		//Recreate the PublicKey Object
		String modu = new String(DatatypeConverter.parseBase64Binary(modulus));//convertFromBase64(modulus);
		String expo = new String(DatatypeConverter.parseBase64Binary(exponent));//convertFromBase64(exponent);
		BigInteger mod = new BigInteger(modu);
		BigInteger exp = new BigInteger(expo);
	    PublicKey serverKey;
		try
		{
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
			serverKey = fact.generatePublic(keySpec);
			return serverKey;
		}
		catch (InvalidKeySpecException e)
		{
			//e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e)
		{
			//e.printStackTrace();
		}
		return null;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private boolean sendAliasRequest(String enc_alias, String enc_password, String enc_modulus1, String enc_modulus2, String enc_exponent) throws IOException
	{
		boolean result = false;
		//create the json object
		Map json=new LinkedHashMap();
		json.put("type","alias-request");
		json.put("id",enc_alias);
		Map json2 = new LinkedHashMap();
		json2.put("modulus1", enc_modulus1);
		json2.put("modulus2", enc_modulus2);
		json2.put("pubExp", enc_exponent);
		json.put("pub", json2);
		json.put("pw",enc_password);
		String jsonText = JSONValue.toJSONString(json);
		
	    JSONObject response_json = sendToServer(jsonText);
		if(response_json==null){
			System.out.println("Error: Could not parse JSON from server!");
			return result;
		}
	    String type;
	    type = (String) response_json.get("type");
	    if(!type.equals("alias-response"))
	    {
	    	//System.out.println("Error: Got the wrong response from the server!");
	    	return result;
	    }
	    result = (boolean) response_json.get("result");
		return result;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private PublicKey sendUserKeyRequest(String enc_alias, String enc_keyowner) throws IOException
	{
		String enc_key_owner; //the encrypted key owner from the server response
	    String enc_modulus1; //the encrypted modulus
	    String enc_modulus2; //the encrypted modulus
	    String enc_exponent;  //the encrypted exponent
		//create the json object
		Map json=new LinkedHashMap();
		json.put("type","public-key-request");
		json.put("id", enc_alias);
		json.put("from", enc_keyowner);
		String jsonText = JSONValue.toJSONString(json);

	    JSONObject response_json = sendToServer(jsonText);
		if(response_json==null){
			System.out.println("Error: Could not parse JSON from server!");
			return null;
		}
	    
	    String type;
	    type = (String) response_json.get("type");
	    if(!type.equals("public-key-response"))
	    {
	    	//System.out.println("Error: Got the wrong response from the server!");
	    	return null;
	    }
	    enc_key_owner = (String) response_json.get("from"); //the encrypted key owner in Base64
	    JSONObject pubKey = (JSONObject) response_json.get("pub");  //the encrypted public key
	    enc_modulus1 = (String) pubKey.get("modulus1"); //the encrypted modulus in Base64
	    enc_modulus2 = (String) pubKey.get("modulus2"); //the encrypted modulus in Base64
	    enc_exponent = (String) pubKey.get("pubExp");  //the encrypted exponent in Base64
		byte[] enc_key_owner_bytes = convertFromBase64(enc_key_owner);
		byte[] key_owner_bytes = rsaDecryptData(enc_key_owner_bytes, privateRSAkey);
		System.out.println("Key Owner: " + new String(key_owner_bytes));
		//got the key encrypted with this users public key - so decrypt it first
		//Recreate the Encrypted Key Object
		byte[] enc_mod1 = convertFromBase64(enc_modulus1);
		byte[] enc_mod2 = convertFromBase64(enc_modulus2);
		byte[] enc_exp = convertFromBase64(enc_exponent);
		EncryptedRSAkey enc_key = new EncryptedRSAkey(enc_mod1,enc_mod2, enc_exp);
		PublicKey userKey = rsaDecryptPublicKey(enc_key, privateRSAkey);
		//return the decrypted public key
		/*KeyFactory fact;
		try
		{	//delete this output if everything is working
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
		}*/
		return userKey;
		
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private boolean sendSendRequest(String enc_recipient, String enc_key, String enc_sender, String enc_message) throws IOException
	{
		//send the message
		boolean result = false;
		//create the json object
		Map json=new LinkedHashMap();
		json.put("type","send-request");
		json.put("to",enc_recipient);
		json.put("key", enc_key);
		json.put("from",enc_sender);
		json.put("msg", enc_message);
		String jsonText = JSONValue.toJSONString(json);

	    JSONObject response_json = sendToServer(jsonText);
		if(response_json==null){
			System.out.println("Error: Could not parse JSON from server!");
			return result;
		}
	    String type;
	    type = (String) response_json.get("type");
	    if(!type.equals("send-response"))
	    {
	    	//System.out.println("Error: Got the wrong response from the server!");
	    	return result;
	    }
	    result = (boolean) response_json.get("result");
	    if(result == false)
	    {
	    	String fail_reason = (String) response_json.get("message");
	    	System.out.println("Error while sending the message!");
	    	System.out.println("Errorreason: " + fail_reason);
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
		json.put("type","fetch-request");
		json.put("to",enc_identifier);
		json.put("pw",enc_password);
		String jsonText = JSONValue.toJSONString(json);

	    JSONObject response_json = sendToServer(jsonText);
		if(response_json==null){
			System.out.println("Error: Could not parse JSON from server!");
			return null;
		}
	    String type;
	    type = (String) response_json.get("type");
	    if(!type.equals("fetch-response"))
	    {
	    	System.out.println("Error: Got an error from the server (no such alias or wrong password)!");
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
		return mails;
	}
}