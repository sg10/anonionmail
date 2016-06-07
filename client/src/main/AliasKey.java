package main;

import java.security.PublicKey;

public class AliasKey 
{
	private String alias;
	private PublicKey publicKey;
	
	public AliasKey(String alias, PublicKey pubKey)
	{
		this.alias = alias;
		this.publicKey = pubKey;
	}

	public String getAlias()
	{
		return alias;
	}

	public PublicKey getPublicKey()
	{
		return publicKey;
	}
}
