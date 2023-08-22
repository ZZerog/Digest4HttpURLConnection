package cz.zerog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpUrlDigestImpl {

    private static MessageDigest digest;

    /**
     * Response header with digest auth info
     */
    private static final String WWWAuthenticate = "WWW-Authenticate";
    private static final String DIGEST = "Digest ";
    private static final String REALM = "realm";
    private static final String ALGORITHM = "algorithm";
    private static final String NONCE = "nonce";
    private static final String QOP = "qop";

    private static final String SHA256 = "SHA-256";
    private static final String SHA256SESS = "SHA-256-sess";
    private static final String MD5 = "MD5";
    private static final String MD5SESS = "MD5-sess";


    /**
     * Test if response code is 401 and if so, try to send digest authenticate
     * @param connection old url connection
     * @param username username
     * @param password password
     * @return new connection with digest authenticate
     * @throws IOException
     */

    public static HttpURLConnection tryAuth(HttpURLConnection connection, final String username, final String password) throws IOException {

        final int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            connection = doAuthReq(connection, username, password);
        }

        return connection;
    }

    /**
     * Send digest authenticate
     * @param oldConnection
     * @param username
     * @param password
     * @return null when error occurred or new connection with digest
     */

    private static HttpURLConnection doAuthReq(final HttpURLConnection oldConnection, final String username, final String password) throws DigestAuthenticationException {

        final String auth = oldConnection.getHeaderField(WWWAuthenticate);

        //test if the response header start with digest, if not, digest auth. cannot use
        if (auth == null || !auth.startsWith(DIGEST)) {
            throw new DigestAuthenticationException("WWW-Authenticate header field is null or does not start with 'Digest '");
        }

        //parse to map
        final HashMap<String, List<String>> authFields = authLineParamsToMap(auth.substring(DIGEST.length()));

        //init and get alg. name
        final String algorithm = initHashAlgAndReturnAlg(authFields.containsKey(ALGORITHM)?authFields.get(ALGORITHM).get(0):null);
        final String nc = getNc(); //nonce counter
        final String cnonce = getCnonce(); //client nonce
        final String qop;

        final String HA1;
        if(!authFields.containsKey(ALGORITHM) || (authFields.containsKey(ALGORITHM)  && !authFields.get(ALGORITHM).get(0).contains("-sess"))) {
            HA1 = hash(joinColon(username, authFields.get(REALM).get(0), password));
        } else if(authFields.containsKey(ALGORITHM) && authFields.get(ALGORITHM).get(0).contains("-sess")) {
            String h = hash(joinColon(username, authFields.get(REALM).get(0), password));
            HA1 = hash(joinColon(h, authFields.get(NONCE).get(0), cnonce));
        } else {
            //unknown value in algorithm, hash cannot be calculated
            throw new DigestAuthenticationException("Cannot calculate HA1, unknown value ("+authFields.get(ALGORITHM).get(0)+") in algorithm");
        }


        final String HA2;
        if(!authFields.containsKey(QOP) || authFields.get(QOP).contains("auth")) {
            qop = "auth";
            HA2 = hash(joinColon(oldConnection.getRequestMethod(), oldConnection.getURL().getPath()));
        } else if(authFields.containsKey(QOP) && authFields.get(QOP).contains("auth-int")) {
            qop = "auth-int";
            //read entity body, response return 401 so is used error stream
            StringBuilder entityBody = new StringBuilder();

            if(oldConnection.getErrorStream() != null) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader((oldConnection.getErrorStream())))) {

                    String output;
                    while ((output = br.readLine()) != null) {
                        entityBody.append(output);
                    }

                } catch (Exception e) {
                    throw new DigestAuthenticationException(e);
                }
            }

            HA2 = hash(joinColon(oldConnection.getRequestMethod(), oldConnection.getURL().getPath(), hash(entityBody.toString())));
        } else {
            //unknown value in qop, cannot calculate 'qop'
            throw new DigestAuthenticationException("Cannot calculate HA2, unknown value ("+authFields.get(QOP).get(0)+") in qop");
        }

        final String response;
        if(!authFields.containsKey(QOP)) {
            response = hash(joinColon(HA1, authFields.get(NONCE).get(0), HA2));
        } else if(authFields.containsKey(QOP) && (authFields.get(QOP).contains("auth-int") || authFields.get(QOP).contains("auth"))) {
            response = hash(joinColon(HA1, authFields.get(NONCE).get(0),nc,cnonce,authFields.get(QOP).get(0), HA2));
        } else {
            //unknown value in qop, cannot calculate 'response'
            throw new DigestAuthenticationException("Cannot calculate response, unknown value ("+authFields.get(QOP).get(0)+") in qop");
        }

        final StringBuilder sb = new StringBuilder();
        sb.append("Digest ");
        sb.append("username").append("=\"").append(username).append("\", ");
        sb.append("realm").append("=\"").append(authFields.get(REALM).get(0)).append("\", ");
        sb.append("nonce").append("=\"").append(authFields.get(NONCE).get(0)).append("\", ");
        sb.append("uri").append("=\"").append(oldConnection.getURL().getPath()).append("\", ");
        sb.append("nc").append("=").append(nc).append(", ");
        sb.append("cnonce").append("=\"").append(cnonce).append("\", ");
        sb.append("qop").append("=").append(qop).append(", ");
        sb.append("algorithm").append("=").append(algorithm).append(", ");
        sb.append("response").append("=\"").append(response).append("\"");

        try {
            final HttpURLConnection connection = (HttpURLConnection) oldConnection.getURL().openConnection();
            connection.addRequestProperty("Authorization", sb.toString());

            return connection;
        } catch (IOException e) {
            throw new DigestAuthenticationException(e);
        }
    }

    /**
     * Init hash algorithm and return algorithm name
     * @param algorithmParam null or name of algorithm
     * @return digest algorithm name
     * @throws DigestAuthenticationException
     */
    private static String initHashAlgAndReturnAlg(final String algorithmParam) throws DigestAuthenticationException {
        if(algorithmParam == null) {
            initAsMD5();
            return MD5;

        } else if(algorithmParam.startsWith(MD5)) {
            initAsMD5();

            if(algorithmParam.equals(MD5SESS)) {
                return MD5SESS;
            }

            return MD5;
        } else if(algorithmParam.startsWith(SHA256)){
            initAsSHA256();

            if(algorithmParam.equals(SHA256SESS)) {
                return SHA256SESS;
            }

            return SHA256;
        } else {
            //unknown value in algorithm, hash cannot be calculated
            throw new DigestAuthenticationException("Unknown value ("+algorithmParam+") in algorithm");
        }
    }

    /**
     * Init hash algorithm as SHA-256
     */
    private static void initAsSHA256() throws DigestAuthenticationException {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new DigestAuthenticationException(e.getMessage());
        }
    }

    /**
     * Init hash algorithm as MD5
     */

    private static void initAsMD5() throws DigestAuthenticationException {
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new DigestAuthenticationException(e.getMessage());
        }
    }

    /**
     * Hash input string
     * @param input as String
     * @return hashed input also as the string
     */
    private static String hash(final String input) {
        digest.reset();
        digest.update(input.getBytes(StandardCharsets.ISO_8859_1));
        return byteArrToHexString(digest.digest());
    }

    /**
     * Generate and get random cnonce value.
     * This value is calculated by browser
     * @return cnonce value
     */
    private static String getCnonce() {
        return hash(""+Math.floor(Math.random() *(10_000_000 - 1000 + 1) + 1000)); //single line -> random number between 1000 and 10000000 and then hashed
    }


    /**
     * Get nonce counter.
     * This value is fixed to 00000001!
     * @return nonce counter as String
     */
    private static String getNc() {
        return "00000001";
    }

    /**
     * Parse WWW-Authenticate header field to map
     * @param authString WWW-Authenticate header line without 'Digest '
     * @return map of key value pairs where key is name of parameter and value is list of values.
     */
    private static HashMap<String, List<String>> authLineParamsToMap(String authString) {
        final HashMap<String, List<String>> fields = new HashMap<>();

        String[] params = authString.split(",");

        for (int i = 0; i < params.length; i++) {
            String param = params[i];

            if(param.contains("=")) {
                appendToMap(fields, param); //single value
            } else {
                appendToMap(fields, params[i - 1]+","+params[i]); //multivalued
            }
        }

        return fields;
    }


    /**
     * Join strings with ':'
     * @param inputs array of strings
     * @return joined string with ':'
     */
    private static String joinColon(final String... inputs) {

        final StringBuilder sb = new StringBuilder();
        for (String input : inputs) {
            sb.append(input).append(":");
        }

        return sb.deleteCharAt(sb.length() - 1).toString(); // remove last ':'
    }

    /**
     * Convert byte array to hex string
     * @param bytes input byte array
     * @return hex string
     */
    private static String byteArrToHexString(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            sb.append(String.format("%02x", aByte)); //must be lowercase
        }
        return sb.toString();
    }

    /**
     * Append key value pair to map. If value contains ',' then it is multivalued
     * @param map where to append
     * @param pairAsLine key value pair as string with '='
     */
    private static void appendToMap(Map<String,List<String>> map,  String pairAsLine) {
        final String[] pair = pairAsLine.split("=");

        final List<String> valList;
        final String value = delQuotes(pair[1].trim());

        //if true, multivalued
        if(value.contains(",")) {
            valList = List.of(value.split(","));
        } else { //single value
            valList = List.of(value);
        }

        map.put(pair[0].trim(), valList);
    }

    /**
     * If string starts and ends with quotes, remove them
     * @param str in string
     * @return out string
     */
    private static String delQuotes(final String str) {
        if(str.startsWith("\"") && str.endsWith("\"")) {
            return str.substring(1, str.length() - 1);
        }

        return str;
    }

    /**
     * Exception for digest auth
     */
    public static class DigestAuthenticationException extends IOException {
        public DigestAuthenticationException(String message) {
            super("Digest Authentication failed, "+message);
        }

        public DigestAuthenticationException(Exception e) {
            super(e);
        }
    }
}

