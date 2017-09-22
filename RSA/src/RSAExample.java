import java.math.BigInteger;
import java.util.Random;

public class RSAExample {
	public static void main(String[] args) {
	    // Each public and private key consists of an exponent and a modulus
	    BigInteger n; // n is the modulus for both the private and public keys
	    BigInteger e; // e is the exponent of the public key
	    BigInteger d; // d is the exponent of the private key

	    Random rnd = new Random();

	    // Step 1: Generate two large random primes.
	    // We use 400 bits here, but best practice for security is 2048 bits.
	    // Change 400 to 2048, recompile, and run the program again and you will
	    // notice it takes much longer to do the math with that many bits.
	    BigInteger p = new BigInteger(400,100,rnd);
	    BigInteger q = new BigInteger(400,100,rnd);

	    // Step 2: Compute n by the equation n = p * q.
	    n = p.multiply(q);

	    // Step 3: Compute phi(n) = (p-1) * (q-1)
	    BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	    
	    // Step 4: Select a small odd integer e that is relatively prime to phi(n).
	    // By convention the prime 65537 is used as the public exponent.
	    e = new BigInteger ("65537");

	    // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
	    d = e.modInverse(phi);
	    
	    System.out.println(" e = " + e);  // Step 6: (e,n) is the RSA public key
	    System.out.println(" d = " + d);  // Step 7: (d,n) is the RSA private key
	    System.out.println(" n = " + n);  // Modulus for both keys
	    
	    // Encode a simple message. For example the letter 'A' in UTF-8 is 65
	    BigInteger m = new BigInteger("65");

	    // Step 8: To encrypt a message M compute C = M^e (mod n)
	    BigInteger c = m.modPow(e, n);
	    
	    // Step 9: To decrypt a message C compute M = C^d (mod n)
	    BigInteger clear = c.modPow(d, n);
	    System.out.println("Cypher text = " + c);
	    System.out.println("Clear text = " + clear); // Should be "65"
	    
	    // Step 8 (reprise) Encrypt the string 'Hello'
	    String s = "RSA is way cool.";
	    m = new BigInteger(s.getBytes()); // m is the original clear text
	    c = m.modPow(e, n);     // Do the encryption, c is the cypher text

	    // Step 9 (reprise) Decrypt...
	    clear = c.modPow(d, n); // Decrypt, clear is the resulting clear text
	    String clearStr = new String(clear.toByteArray());  // Decode to a string

	    System.out.println("Cypher text = " + c);
	    System.out.println("Clear text = " + clearStr);
	  }


}
