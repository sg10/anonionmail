package main;

public class EncryptedRSAkey
{
	private byte[] mod1;
	private byte[] mod2;
	private byte[] exp;
	
	public EncryptedRSAkey(byte[] mod1, byte[] mod2, byte[] exp)
	{
		this.exp = exp;
		this.mod1 = mod1;
		this.mod2 = mod2;
	}
	
	public byte[] getMod1()
	{
		return mod1;
	}
	
	public byte[] getMod2()
	{
		return mod2;
	}
	
	public byte[] getExp()
	{
		return exp;
	}	
}
