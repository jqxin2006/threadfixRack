package com.denimgroup.threadfix.service;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.Reader;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

/**
 * This class is included because it is sometimes useful for these methods to appear
 * outside of the AbstractChannelImporter. For example, when trying to determine the type
 * of scanner that produced an uploaded file, the readSAXInput method can be a helpful tool.
 * 
 * @author mcollins
 *
 */
public final class ScanUtils {
	
	private static final SanitizedLogger STATIC_LOGGER = new SanitizedLogger(ScanUtils.class);

	private ScanUtils(){}
	
	/**
	 * This method checks through the XML with a blank parser to determine
	 * whether SAX parsing will fail due to an exception.
	 */
	public static boolean isBadXml(InputStream inputStream) {
		try {
			readSAXInput(new DefaultHandler(), inputStream);
		} catch (SAXException e) {
			STATIC_LOGGER.warn("Trying to read XML returned the error " + e.getMessage());
			return true;
		} catch (IOException e) {
			STATIC_LOGGER.warn("Trying to read XML returned the error " + e.getMessage());
			return true;
		} finally {
			closeInputStream(inputStream);
		}

		return false;
	}
	
	/**
	 * This method with one argument sets up the SAXParser and inputStream correctly
	 * and executes the parsing. With two it adds a completion code and exception handling.
	 * @param handler
	 * @param completionCode
	 */
	public static void readSAXInput(DefaultHandler handler, String completionCode, InputStream stream) {
		try {
			readSAXInput(handler, stream);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			if (!e.getMessage().equals(completionCode))
				e.printStackTrace();
		} finally {
			closeInputStream(stream);
		}
	}
	
	public static void closeInputStream(InputStream stream) {
		if (stream != null) {
			try {
				stream.close();
			} catch (IOException ex) {
				STATIC_LOGGER.warn("Closing an input stream failed.", ex);
			}
		}
	}
	
	private static void readSAXInput(DefaultHandler handler, InputStream stream) throws SAXException, IOException {
		XMLReader xmlReader = XMLReaderFactory.createXMLReader();
		xmlReader.setContentHandler(handler);
		xmlReader.setErrorHandler(handler);
				
		// Wrapping the inputStream in a BufferedInputStream allows us to mark and reset it
		BufferedInputStream newStream = new BufferedInputStream(stream);
		
		// UTF-8 contains 3 characters at the start of a file, which is a problem. = null;
		// The SAX parser sees them as characters in the prolog and throws an exception.
		// This code removes them if they are present.
		newStream.mark(4);
		
		if (newStream.read() == 239) {
			newStream.read(); newStream.read();
		} else
			newStream.reset();
		
		Reader fileReader = new InputStreamReader(newStream,"UTF-8");
		InputSource source = new InputSource(fileReader);
		source.setEncoding("UTF-8");
		xmlReader.parse(source);
	}
	
	public static boolean isZip(String fileName) {
		RandomAccessFile file = null;
		try {
			file = new RandomAccessFile(new File(fileName), "r");  
			// these are the magic bytes for a zip file
	        return file.readInt() == 0x504B0304;
		} catch (FileNotFoundException e) {
			STATIC_LOGGER.warn("The file was not found. Check the usage of this method.", e);
		} catch (IOException e) {
			STATIC_LOGGER.warn("IOException. Weird.", e);
		} finally {
			if (file != null) {
				try {
					file.close();
				} catch (IOException e) {
					STATIC_LOGGER.error("Encountered IOException when attempting to close a file.", e);
				}
			}
		}
		
		return false;
	}
}
