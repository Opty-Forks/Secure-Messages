package pt.tecnico;

import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.*;

import com.google.gson.*;

public class SecureClient {

	// Buffer Size for Receiving a UDP Packet.
	private static final int BUFFER_SIZE = 65507;

	public static void main(String[] args) throws Exception {
		// Check Arguments
		if (args.length < 5) {
			System.err.println("Argument(s) Missing!");
			return;
		}
		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final int serverPort = Integer.parseInt(args[1]);
		Key pubKey = CryptoExample.readPublicKey(args[2]);
		Key privKey = CryptoExample.readPrivateKey(args[3]);
		Key secretKey = CryptoExample.readSecretKey(args[4]);

		Map<Long, Long> clientFreshness = new HashMap<>();

		new Timer().schedule(new TimerTask() {
			public void run()  {
				synchronized (clientFreshness) {
					clientFreshness.entrySet().removeIf(e -> Math.abs(System.currentTimeMillis() - e.getValue()) > 1000);
				}
			}
		}, 0, 1000);

		// Create Socket
		DatagramSocket socket = new DatagramSocket();

        // Check Arguments
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
		infoJson.addProperty("from", "Alice");
		infoJson.addProperty("to", "Bob");
		infoJson.addProperty("ts", System.currentTimeMillis());
		infoJson.addProperty("nonce", new Random().nextLong());
		requestJson.add("info", infoJson);

		String bodyText = "Hello." + System.lineSeparator() + "Do you want to meet tomorrow?";
		requestJson.addProperty("body", bodyText);
		System.out.println("Request Message: " + requestJson);

		// Send request
		byte[] requestData = requestJson.toString().getBytes();
		System.out.printf("%d Bytes %n", requestData.length);
		byte[] requestEncrypted = CryptoLib.addConfidentialityAndIntegrity(requestData, privKey, secretKey);
		socket.send(new DatagramPacket(requestEncrypted, requestEncrypted.length, serverAddress, serverPort));
		/* Freshness Attack
		socket.send(clientPacket);
		socket.send(clientPacket);
		*/
		System.out.printf("Request Packet Sent To '%s:%d'!%n", serverAddress, serverPort);

		// Receive Response
		byte[] buf = new byte[BUFFER_SIZE];
		DatagramPacket replyPacket = new DatagramPacket(buf, buf.length);
		System.out.println("Wait for Response Packet (...)");
		socket.receive(replyPacket);
		System.out.printf("Received Packet From: '%s:%d'!%n", replyPacket.getAddress(), replyPacket.getPort());
		System.out.printf("%d Bytes %n", replyPacket.getLength());

		ByteBuffer dataBuf = ByteBuffer.allocate(replyPacket.getLength() - CryptoLib.SIGNATURE_SIZE);
		if (!CryptoLib.checkConfidentialityAndIntegrity(replyPacket.getData(), replyPacket.getLength(), pubKey, secretKey, dataBuf)) {
			return;
		}

		// Convert Response to String
		String reply = new String(dataBuf.array(), 0, dataBuf.position());
		System.out.println("Received Response: " + reply);

		// Parse JSON and Extract Arguments
		JsonObject replyJson = JsonParser.parseString(reply).getAsJsonObject();
		Map<String, Long> freshness = CryptoLib.getFreshness(replyJson);
		synchronized (clientFreshness) {
			if (!CryptoLib.checkFreshness(clientFreshness, freshness)) {
				return;
			}
		}

		// Close Socket
		socket.close();
		System.out.println("Socket closed");
		System.exit(0);
	}
}
