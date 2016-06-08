package main;

public class EncryptedRSAkey
{
	private byte[] mod;
	private byte[] exp;
	
	public EncryptedRSAkey(byte[] mod, byte[] exp)
	{
		this.exp = exp;
		this.mod = mod;
	}
	
	public byte[] getMod()
	{
		return mod;
	}
	
	public byte[] getExp()
	{
		return exp;
	}	
}
