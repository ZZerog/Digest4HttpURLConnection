package cz.zerog;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

public class Example {



    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        //String url = "http://192.168.0.133/images/snapshot.jpg"; //real IP video camera url

        call("http://httpbin.org/digest-auth/auth/Joe/joepasswd/MD5", "Joe", "joepasswd");
        call("http://httpbin.org/digest-auth/auth/Joe/joepasswd/MD5-sess", "Joe", "joepasswd");
        call("http://httpbin.org/digest-auth/auth/Joe/joepasswd/SHA-256", "Joe", "joepasswd");
        call("http://httpbin.org/digest-auth/auth/Joe/joepasswd/SHA-256-sess", "Joe", "joepasswd");

    }

    private static void call(String url, String user, String password) throws IOException {

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.connect();


        //apply digest auth
        connection = HttpUrlDigestImpl.tryAuth(connection, user, password);

        if(connection.getResponseCode() == HttpURLConnection.HTTP_OK) { //200
            System.out.println("Success "+url);
        } else {
            System.out.println("FAIL ("+connection.getResponseCode()+") "+url);
        }
    }
}
