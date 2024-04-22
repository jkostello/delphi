import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Java_server {

    public static void main(String[] args) throws Exception {
        int port = 8000;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new MyHandler());
        server.setExecutor(null); // use the default executor
        server.start();
        System.out.println("Server started on port " + port);
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            URI uri = exchange.getRequestURI();
            if (uri.getPath().equals("/encrypt")) {
                handleEncrypt(exchange);
            } else if (uri.getPath().equals("/decrypt")) {
                handleDecrypt(exchange);
            } else {
                sendResponse(exchange, 405, "Method Not Allowed");
            }
        }

        // Call with body: "password key"
        private void handleDecrypt(HttpExchange exchange) throws IOException {
            System.out.println("Called Decrypt"); // Debug

            InputStreamReader isr =  new InputStreamReader(exchange.getRequestBody(),"utf-8");
            BufferedReader br = new BufferedReader(isr);
            int b;
            StringBuilder buf = new StringBuilder(512);
            while ((b = br.read()) != -1) {
                buf.append((char) b);
            }
            br.close();
            isr.close();

            System.out.println("body = " + buf.toString()); // Debug
            String encrypted = buf.toString().split(" ")[0];
            byte[] encryptedAsBytes = Base64.getDecoder().decode(encrypted);
            String key = (buf.toString()).split(" ")[1];
            String decrypted = Encryption.decrypt(encryptedAsBytes, key);
            sendResponse(exchange, 200, decrypted);
        }

        // Call with body: "password key"
        private void handleEncrypt(HttpExchange exchange) throws IOException {
            System.out.println("Called Encrypt"); // Debug

            InputStreamReader isr =  new InputStreamReader(exchange.getRequestBody(),"utf-8");
            BufferedReader br = new BufferedReader(isr);
            int b;
            StringBuilder buf = new StringBuilder(512);
            while ((b = br.read()) != -1) {
                buf.append((char) b);
            }
            br.close();
            isr.close();

            System.out.println("body = " + buf.toString()); // Debug
            String password = (buf.toString()).split(" ")[0];
            String key = buf.toString().split(" ")[1];
            byte[] encrypted = Encryption.encrypt(password, key);
            String encoded =  Base64.getEncoder().encodeToString(encrypted);
            sendResponse(exchange, 200, encoded);
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
            exchange.sendResponseHeaders(statusCode, message.length());
            OutputStream os = exchange.getResponseBody();
            os.write(message.getBytes(StandardCharsets.UTF_8));
            os.close();
            exchange.close();
        }
    }
}