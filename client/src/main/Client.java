package main;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Client 
{
	private String identifier = new String();
	//TODO: create public key list for other user
	//TODO: create keypair-attribute for this user (datatype of a rsa key?)
	private String publicKey_server = new String(); //TODO: create field for the public key of the server(RSA KEY)
	
	public Client()
	{
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
			return false;
		
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
		if(publicKey_server.isEmpty())
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		System.out.println("Logging in with alias and password:");
		String alias = new String();
		String password = new String();
		System.out.println("Please enter your alias...");
		boolean is_valid = false;
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
		password = readInput(); //TODO: hash the password
		//TODO: send the information to the server (encrypted with servers public key)
		identifier = alias; //if the server says OK
	}
	
	private void request_ServerKey()
	{
		System.out.print("Requesting public key from the server...");
		//TODO: connecting to the server and requesting his public key
		System.out.print("OK\n");
		publicKey_server = "DEADBEEF"; //TODO: store the actual key...
		startClient();
	}
	
	private void request_alias()
	{
		if(publicKey_server.isEmpty())
		{
			System.out.println("ERROR: You have to first get the public key of the server!");
			startClient();
			return;
		}
		String alias = new String();
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
		//TODO: Create an RSA keypair and send the alias with the public key to the server (both encrypted with servers public key)
		//if the server responds with an ok do:
		identifier = alias;
		System.out.println("Alias saved!\n");
		startClient();
	}
	private void request_UserKey(String user_alias)
	{
		System.out.print("...requesting the public key from the user...");
		//TODO: request the key for the entered alias from the server and return it
		System.out.print("OK\n");
	}
	private void send_message()
	{
		if(publicKey_server.isEmpty())
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
		boolean is_valid = false;
		boolean send_message;
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
		//TODO: check if the public key of this user is already stored in the list of public keys
		request_UserKey(user_alias); //if not then request it
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
		//TODO: Encrypt the recipient with server public key, encrypt message with AES and AES key with recipient public key
		//TODO: send message to the server
		System.out.println("Message has been sent!\n");
		startClient();
	}
	private void fetch_messages()
	{
		if(publicKey_server.isEmpty())
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
		System.out.println("Please enter your password...");
		int message_count = 0;
		String password = readInput();
		//TODO: hash the password
		//TODO: send the fetch request to the server and store the messages in a list
		
		System.out.println("You have " + Integer.toString(message_count) + " new messages: \n");
		//TODO: Iterate through the list and print one message at a time, waiting for the user to press enter to show the next one
		startClient();
	}
}
