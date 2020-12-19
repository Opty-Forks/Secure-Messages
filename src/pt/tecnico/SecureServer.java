package pt.tecnico;

import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.*;

import com.google.gson.*;


public class SecureServer {

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 Bytes (8 byte header + 65,527 Bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 Bytes (65,535 − 8 byte UDP header − 20 byte IP header.
	 */
	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	// Buffer Size for Receiving a UDP Packet.
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	public static void main(String[] args) throws Exception {
		// Check Arguments
		if (args.length < 4) {
			System.err.println("Argument(s) Missing!");
			return;
		}
		final int port = Integer.parseInt(args[0]);
		Key pubKey = CryptoExample.readPublicKey(args[1]);
		Key privKey = CryptoExample.readPrivateKey(args[2]);
		Key secretKey = CryptoExample.readSecretKey(args[3]);

		Map<Long, Long> serverFreshness = new HashMap<>();

		new Timer().schedule(new TimerTask() {
			public void run()  {
				synchronized (serverFreshness) {
					serverFreshness.entrySet().removeIf(e -> Math.abs(System.currentTimeMillis() - e.getValue()) > 1000);
				}
			}
		}, 0, 1000);

		// Create Server Socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will Receive Packets on Port: %d %n", port);

		// Wait for Client Packets
		byte[] buf = new byte[BUFFER_SIZE];
		while (true) {
			// Receive Packet
			DatagramPacket requestPacket = new DatagramPacket(buf, buf.length);
			socket.receive(requestPacket);
			System.out.printf("Received Request Packet From: '%s:%d'!%n", requestPacket.getAddress(), requestPacket.getPort());
			System.out.printf("%d Bytes %n", requestPacket.getLength());

			ByteBuffer dataBuf = ByteBuffer.allocate(requestPacket.getLength() - CryptoLib.SIGNATURE_SIZE);
			if (!CryptoLib.checkConfidentialityAndIntegrity(requestPacket.getData(), requestPacket.getLength(), pubKey, secretKey, dataBuf)) {
				continue;
			}

			// Convert Request to String
			String request = new String(dataBuf.array(), 0, dataBuf.position());
			System.out.println("Received Request: " + request);

			// Parse JSON and Extract Arguments
			JsonObject requestJson = JsonParser.parseString(request).getAsJsonObject();
			Map<String, Long> freshness = CryptoLib.getFreshness(requestJson);
			synchronized (serverFreshness) {
				if (!CryptoLib.checkFreshness(serverFreshness, freshness)) {
					return;
				}
			}

			// Create Response Message
			JsonObject replyJson = JsonParser.parseString("{}").getAsJsonObject();
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			infoJson.addProperty("from", "Bob");
			infoJson.addProperty("to", requestJson.get("info").getAsJsonObject().get("from").getAsString());
			infoJson.addProperty("ts", System.currentTimeMillis());
			infoJson.addProperty("nonce", new Random().nextLong());
			replyJson.add("info", infoJson);
			String bodyText = "Yes. See you tomorrow!";
			replyJson.addProperty("body", bodyText);
			System.out.println("Response Message: " + replyJson);

			// Send Response
			byte[] replyData = replyJson.toString().getBytes();
			System.out.printf("%d Bytes %n", replyData.length);
			byte[] replyEncrypted = CryptoLib.addConfidentialityAndIntegrity(replyData, privKey, secretKey);
			socket.send(new DatagramPacket(replyEncrypted, replyEncrypted.length, requestPacket.getAddress(), requestPacket.getPort()));
			System.out.printf("Response Packet Sent To '%s:%d'!%n", requestPacket.getAddress(), requestPacket.getPort());
		}
	}
}
