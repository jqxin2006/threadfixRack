package com.denimgroup.threadfix.webservices.tests;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class HttpRestUtils {
	
	protected final Log log = LogFactory.getLog("HttpRestUtils");
	
	public final String API_KEY_ERROR = "Authentication failed, check your API Key.";
	
	private String url = null;
	private String key = null;
	
	public String httpPostFile(String request, String fileName, String[] paramNames,
			String[] paramVals) {
		File file = new File(fileName);
		return httpPostFile(request, file, paramNames,
				paramVals);
	}
	
	public String httpPostFile(String request, File file, String[] paramNames,
			String[] paramVals) {
		
		log.debug("Requesting " + request);
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));

		PostMethod filePost = new PostMethod(request);
		
		filePost.setRequestHeader("Accept", "application/json");
		
		try {
			Part[] parts = new Part[paramNames.length + 1];
			parts[paramNames.length] = new FilePart("file", file);

			for (int i = 0; i < paramNames.length; i++) {
				parts[i] = new StringPart(paramNames[i], paramVals[i]);
			}

			filePost.setRequestEntity(new MultipartRequestEntity(parts,
					filePost.getParams()));
			
			filePost.setContentChunked(true);
			HttpClient client = new HttpClient();
			int status = client.executeMethod(filePost);
			if (status != 200) {
				log.warn("Status was not 200.");
			}
			
			InputStream responseStream = filePost.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return IOUtils.toString(responseStream);
			}

		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return "There was an error and the POST request was not finished.";
	}

	public String httpPost(String request, String[] paramNames,
			String[] paramVals) {
		
		log.debug("Requesting " + request);
		
		Protocol.registerProtocol("https", new Protocol("https", new HttpRestUtils.AcceptAllTrustFactory(), 443));

		PostMethod post = new PostMethod(request);
		
		post.setRequestHeader("Accept", "application/json");
		
		try {
			for (int i = 0; i < paramNames.length; i++) {
				if (paramNames[i] != null && paramVals[i] != null)
					post.addParameter(paramNames[i], paramVals[i]);
			}
			
			HttpClient client = new HttpClient();
			int status = client.executeMethod(post);
			if (status != 200) {
				log.warn("Status was not 200.");
			}
			
			InputStream responseStream = post.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return IOUtils.toString(responseStream);
			}

		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return "There was an error and the POST request was not finished.";
	}

	public String httpGet(String urlStr) {
		
		log.debug("Requesting " + urlStr);
		
		Protocol.registerProtocol("https", new Protocol("https", new AcceptAllTrustFactory(), 443));
		GetMethod get = new GetMethod(urlStr);
		
		get.setRequestHeader("Accept", "application/json");
		
		HttpClient client = new HttpClient();
		try {
			int status = client.executeMethod(get);
			if (status != 200) {
				log.warn("Status was not 200.");
			}
			
			InputStream responseStream = get.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return IOUtils.toString(responseStream);
			}
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "There was an error and the GET request was not finished.";
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * @param responseContents
	 * @return
	 */
	public JSONObject getJSONObject(String responseContents) {
		if (responseContents == null) {
			return null;
		}
		try {
			return new JSONObject(responseContents);
		} catch (JSONException e) {
			return null;
		}
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * @param object
	 * @return
	 */
	public Integer getId(JSONObject object) {
		if (object == null) {
			return null;
		}
		try {
			return object.getInt("id");
		} catch (JSONException e) {
			return null;
		}
	}
	
	public String getString(JSONObject object, String key) {
		if (object == null || key == null) {
			return null;
		}
		try {
			return object.getString(key);
		} catch (JSONException e) {
			return null;
		}
	}
	
	public JSONArray getJSONArray(String responseContents) {
		if (responseContents == null) {
			return null;
		}
		try {
			return new JSONArray(responseContents);
		} catch (JSONException e) {
			return null;
		}
	}

	/**
	 * This method is a wrapper for RandomStringUtils.random with a preset character set.
	 * @return random string
	 */
	protected static String getRandomString(int length) {
		return RandomStringUtils.random(length,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	}
	
	// These methods help persist the URL and API Key so they don't have to be entered each time.
	public void setUrl(String url) {
		this.url = url;
	}
	
	public void setKey(String key) {
		this.key = key;
	}
	
	public String getUrl() {
		return url == null ? "https://localhost:8443/threadfix/rest" : url;
	}
	
	public String getKey() {
		return key;
	}

	/**
	 * These two classes allow the self-signed SSL cert to work. We might be able to cut this down.
	 * @author mcollins
	 *
	 */
	public static class AcceptAllTrustManager implements X509TrustManager {
	    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
	    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
	    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
	}

	public class AcceptAllTrustFactory implements ProtocolSocketFactory {

		private SSLContext sslContext = null;

		private SSLContext createAcceptAllSSLContext() {
			try {
				AcceptAllTrustManager acceptAllTrustManager = new AcceptAllTrustManager();
				SSLContext context = SSLContext.getInstance("TLS");
				context.init(null,
						new AcceptAllTrustManager[] { acceptAllTrustManager },
						null);
				return context;
			} catch (KeyManagementException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			return null;
		}

	    private SSLContext getSSLContext() {
	        if(this.sslContext == null) {
	            this.sslContext = createAcceptAllSSLContext();
	        }

	        return this.sslContext;
	    }

	    public Socket createSocket(String host, int port, InetAddress clientHost, int clientPort) throws IOException {
	        return getSSLContext().getSocketFactory().createSocket(host, port, clientHost, clientPort);
	    }

	    public Socket createSocket(final String host, final int port, final InetAddress localAddress, final int localPort, final HttpConnectionParams params) throws IOException {
	        if(params == null) {
	            throw new IllegalArgumentException("Parameters may not be null");
	        }

	        int timeout = params.getConnectionTimeout();
	        SocketFactory socketFactory = getSSLContext().getSocketFactory();

	        if(timeout == 0) {
	            return socketFactory.createSocket(host, port, localAddress, localPort);
	        }

	        else {
	            Socket socket = socketFactory.createSocket();
	            SocketAddress localAddr = new InetSocketAddress(localAddress, localPort);
	            SocketAddress remoteAddr = new InetSocketAddress(host, port);
	            socket.bind(localAddr);
	            socket.connect(remoteAddr, timeout);
	            return socket;
	        }
	    }

	    public Socket createSocket(String host, int port) throws IOException {
	        return getSSLContext().getSocketFactory().createSocket(host, port);
	    }

	    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
	        return getSSLContext().getSocketFactory().createSocket(socket, host, port, autoClose);
	    }
	}
}
