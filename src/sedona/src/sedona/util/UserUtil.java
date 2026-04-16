//
// Copyright (c) 2008 Tridium, Inc.
// Licensed under the Academic Free License version 3.0
//
// History:
//   19 Jul 08  Brian Frank  Creation
//

package sedona.util;

import java.security.SecureRandom;
import java.security.*;
import sedona.Buf;

/**
 * UserUtil provides utility functions for working with Sedona
 * users and their associated SHA-1 digests.
 */
public class UserUtil
{

  /** Legacy unsalted credential: SHA1("user:pass"). */
  public static byte[] credentials(String user, String pass)
  {
    try
    {
      String text = user + ":" + pass;
      return MessageDigest.getInstance("SHA-1").digest(text.getBytes("UTF-8"));
    }
    catch (Exception e)
    {
      throw new RuntimeException(e.toString());
    }
  }

  /**
   * Salted iterated-SHA1 credential, suitable for the post-fix
   * sys::User.cred field when paired with sys::User.credSalt. Computes
   * SHA1(salt || utf8(pass)) and re-hashes the 20-byte digest iter-1
   * more times. The username is intentionally not part of the
   * pre-image under this scheme (salt provides per-account uniqueness).
   */
  public static byte[] credentialsSalted(String pass, byte[] salt, int iter)
  {
    if (salt == null || salt.length == 0)
      throw new IllegalArgumentException("salt required");
    if (iter < 1) throw new IllegalArgumentException("iter must be >= 1");
    try
    {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      md.update(salt);
      md.update(pass.getBytes("UTF-8"));
      byte[] h = md.digest();
      for (int i = 1; i < iter; i++)
      {
        md.reset();
        h = md.digest(h);
      }
      return h;
    }
    catch (Exception e)
    {
      throw new RuntimeException(e.toString());
    }
  }

  /** Generate a fresh 16-byte random salt. */
  public static byte[] newSalt()
  {
    byte[] s = new byte[16];
    new SecureRandom().nextBytes(s);
    return s;
  }

  public static void main(String[] args)
  {
    if (args.length < 2 || args.length > 3)
    {
      System.out.println("usage: UserUtil <user> <pass> [--legacy]");
      return;
    }

    String user = args[0];
    String pass = args[1];
    boolean legacy = args.length == 3 && "--legacy".equals(args[2]);

    Buf buf;
    byte[] salt = null;
    if (legacy)
    {
      buf = new Buf(credentials(user, pass));
    }
    else
    {
      salt = newSalt();
      buf = new Buf(credentialsSalted(pass, salt, 4096));
    }

    System.out.println("User:   " + user + ":" + pass);
    if (salt != null) System.out.println("Salt:   " + new Buf(salt));
    System.out.println("Iter:   " + (legacy ? 1 : 4096));
    System.out.println("Digest: " + buf);
    System.out.println("Base64: " + buf.encodeString());
  }

}
