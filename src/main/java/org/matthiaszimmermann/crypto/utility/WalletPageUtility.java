package org.matthiaszimmermann.crypto.utility;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import org.matthiaszimmermann.crypto.core.Mnemonic;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

public class WalletPageUtility extends HtmlUtility {

	public static final String UTC_DATE_TIME_PATTERN = "'UTC 'yyyy-MM-dd' 'HH:mm:ss.nVV";
	
	// TODO verify version with the one in the pom.xml
	public static final String VERSION = "0.1.0-SNAPSHOT";
	public static final String REPOSITORY = "https://github.com/matthiaszimmermann/TODO";

	public static final String TITLE = "%s Paper Wallet (%s)";
	public static final String LOGO = "/%s_logo.png"; 

	public static final String CSS_CLEARFIX = "clearfix";
	public static final String CSS_ADDRESS_ROW = "address-row";
	public static final String CSS_COLUMN = "column";
	public static final String CSS_FILL = "fill-right";
	public static final String CSS_NOTES = "notes";
	public static final String CSS_CONTENT = "content";
	public static final String CSS_CAPTION = "caption";
	public static final String CSS_FOOTER = "footer-content";
	public static final String CSS_IMG_ADDRESS = "img-address";
	public static final String CSS_IMG_SECRET = "img-secret";
	public static final String CSS_IMG_WALLET = "img-wallet";

	public static final String [] CSS_STYLES = {
			"html * { font-family:Verdana, sans-serif; }",
			String.format(".%s::after { content: \"\"; clear:both; display:table; }", CSS_CLEARFIX),
			String.format(".%s { background-color:#eef; }", CSS_ADDRESS_ROW),
			"@media screen {",
			String.format(".%s { float:left; padding: 15px; }", CSS_COLUMN), 
			String.format(".%s { overflow:auto; padding:15px; }", CSS_FILL),
			String.format(".%s { height:256px; background-color:#fff; }", CSS_NOTES),
			String.format(".%s { padding:15px; background-color:#efefef; font-family:monospace; word-wrap: break-word; }", CSS_CONTENT),
			String.format(".%s { margin-bottom:6px; font-size:smaller;}", CSS_CAPTION),
			String.format(".%s { font-size:small; }", CSS_FOOTER),
			String.format(".%s { display:block; height:256px; }", CSS_IMG_ADDRESS),
			String.format(".%s { display:block; height:256px; margin-top: -12px; margin-left: -12px; position: relative; z-index: -1;}", CSS_IMG_SECRET),
			String.format(".%s { display:block; height:400px }", CSS_IMG_WALLET),
			"}",
			"@media print {",
			String.format(".%s { float:left; padding:8pt; }", CSS_COLUMN), 
			String.format(".%s { overflow:auto; padding:8pt; }", CSS_FILL),
			String.format(".%s { height:100pt; border-style:solid; border-width:1pt; }", CSS_NOTES),
			String.format(".%s { background-color:#efefef; font-family:monospace; font-size:6pt; word-wrap: break-word; }", CSS_CONTENT),
			String.format(".%s { margin-top:2pt; font-size:smaller;}", CSS_CAPTION),
			String.format(".%s { font-size:6pt; }", CSS_FOOTER),
			String.format(".%s { display:block; height:100pt; }", CSS_IMG_ADDRESS),
			String.format(".%s { display:block; height:100pt; margin-top: -5pt; margin-left: -5pt; position: relative; z-index: -1;}", CSS_IMG_SECRET),
			String.format(".%s { display:block; height:180pt }", CSS_IMG_WALLET),
			"}",
	};

	public static String createHtml(Wallet wallet) {
		Protocol protocol = wallet.getProtocol();
		Technology technology = protocol.getTechnology();
		String address = wallet.getAccount().getAddress();
		String seed = wallet.getSeed();
		String mnemonic = Mnemonic.convert(wallet.getMnemonicWords());
		String walletFileContent = wallet.toString();

		byte [] logo = FileUtility.getResourceAsBytes(getLogo(technology));
		byte [] addressQrCode = QrCodeUtility.contentToPngBytes(address, 256);
		byte [] secretQrCode = QrCodeUtility.contentToPngBytes(seed, 256);
		byte [] walletQrCode = QrCodeUtility.contentToPngBytes(walletFileContent, 400);

		StringBuffer html = new StringBuffer();

		// header
		HtmlUtility.addOpenElements(html, HtmlUtility.HTML, HtmlUtility.HEAD);
		HtmlUtility.addTitle(html, getTitle(protocol));
		HtmlUtility.addStyles(html, CSS_STYLES);
		HtmlUtility.addCloseElements(html, HtmlUtility.HEAD);

		// body
		HtmlUtility.addOpenElements(html, HtmlUtility.BODY);
		HtmlUtility.addHeader2(html, getTitle(protocol));

		// add 1st row
		HtmlUtility.addOpenDiv(html, CSS_CLEARFIX, CSS_ADDRESS_ROW);

		// logo
		HtmlUtility.addOpenDiv(html, CSS_COLUMN);
		HtmlUtility.addEncodedImage(html, logo, 256, CSS_IMG_ADDRESS);
		HtmlUtility.addCloseDiv(html);

		// account address
		HtmlUtility.addOpenDiv(html, CSS_COLUMN);
		HtmlUtility.addEncodedImage(html, addressQrCode, 256, CSS_IMG_ADDRESS);
		HtmlUtility.addParagraph(html, "QR Code Address", CSS_CAPTION);
		HtmlUtility.addCloseDiv(html);

		// notes
		HtmlUtility.addOpenDiv(html, CSS_FILL);
		HtmlUtility.addOpenDiv(html, CSS_NOTES);
		HtmlUtility.addCloseDiv(html);
		HtmlUtility.addParagraph(html, "Notes", CSS_CAPTION);
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addCloseDiv(html);

		// add 2nd row
		HtmlUtility.addOpenDiv(html, CSS_CLEARFIX);

		// qr code for seed		
		HtmlUtility.addOpenDiv(html, CSS_COLUMN);
		HtmlUtility.addParagraph(html, "QR Code Seed", CSS_CAPTION);
		HtmlUtility.addEncodedImage(html, secretQrCode, 200, CSS_IMG_SECRET);
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addOpenDiv(html, CSS_FILL);

		HtmlUtility.addParagraph(html, "Address", CSS_CAPTION);
		HtmlUtility.addOpenDiv(html, CSS_CONTENT);
		HtmlUtility.addContent(html, address);
		HtmlUtility.addCloseDiv(html);

		if(!seed.equals(mnemonic)) {
			HtmlUtility.addParagraph(html, "Seed", CSS_CAPTION);
			HtmlUtility.addOpenDiv(html, CSS_CONTENT);
			HtmlUtility.addContent(html, seed);
			HtmlUtility.addCloseDiv(html);
		}

		HtmlUtility.addParagraph(html, "Mnemonic", CSS_CAPTION);
		HtmlUtility.addOpenDiv(html, CSS_CONTENT);
		HtmlUtility.addContent(html, mnemonic);
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addCloseDiv(html);
		HtmlUtility.addCloseDiv(html);

		// add 3rd row
		HtmlUtility.addOpenDiv(html, CSS_CLEARFIX);

		// qr code for wallet file		
		HtmlUtility.addOpenDiv(html, CSS_COLUMN);
		HtmlUtility.addParagraph(html, "QR Code Wallet File", CSS_CAPTION);
		HtmlUtility.addEncodedImage(html, walletQrCode, 500, CSS_IMG_WALLET);
		HtmlUtility.addCloseDiv(html);

		// address, pass phrase, wallet file, file name
		HtmlUtility.addOpenDiv(html, CSS_FILL);

		HtmlUtility.addParagraph(html, "Pass Phrase", CSS_CAPTION);
		HtmlUtility.addOpenDiv(html, CSS_CONTENT);
		HtmlUtility.addContent(html, wallet.getPassPhrase());
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addParagraph(html, "File Content", CSS_CAPTION);
		HtmlUtility.addOpenDiv(html, CSS_CONTENT);
		HtmlUtility.addContent(html, walletFileContent);
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addParagraph(html, "File Name", CSS_CAPTION);
		HtmlUtility.addOpenDiv(html, CSS_CONTENT);
		HtmlUtility.addContent(html, wallet.getFileName());
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addParagraph(html, "Creation Date", CSS_CAPTION);
		HtmlUtility.addOpenDiv(html, CSS_CONTENT);
		HtmlUtility.addContent(html, getCurrentDateTimeUTC());
		HtmlUtility.addCloseDiv(html);

		HtmlUtility.addCloseDiv(html);		
		HtmlUtility.addCloseDiv(html);		

		// add footer content
		String footer = String.format("Page created with Paper Wallet Generator [%s] V %s", REPOSITORY, VERSION);
		HtmlUtility.addOpenFooter(html, CSS_FOOTER);
		HtmlUtility.addContent(html, footer);
		HtmlUtility.addCloseFooter(html);

		HtmlUtility.addCloseElements(html, HtmlUtility.BODY, HtmlUtility.HTML);

		return html.toString();
	}

	private static String getCurrentDateTimeUTC() {
		DateTimeFormatter format = DateTimeFormatter.ofPattern(UTC_DATE_TIME_PATTERN);
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

        return now.format(format);
	}

	private static String getLogo(Technology technology) {
		return String.format(LOGO, technology.name().toLowerCase());
	}

	private static String getTitle(Protocol protocol) {
		Technology technology = protocol.getTechnology();
		Network network = protocol.getNetwork();
		return String.format(TITLE, technology, network);
	}
}
