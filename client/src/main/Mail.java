package main;

public class Mail 
{
	private String aes_key;
	private String sender_field;
	private String timestamp;
	private String message;

	public Mail(String aes_key, String sender_field, String timestamp, String messsage)
	{
		this.aes_key = aes_key;
		this.message = messsage;
		this.sender_field = sender_field;
		this.timestamp = timestamp;
	}

	public String getAes_key()
	{
		return aes_key;
	}

	public String getSender_field()
	{
		return sender_field;
	}

	public String getTimestamp()
	{
		return timestamp;
	}

	public String getMessage()
	{
		return message;
	}
	
}
