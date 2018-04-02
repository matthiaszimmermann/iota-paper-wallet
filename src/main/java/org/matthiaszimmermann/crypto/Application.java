package org.matthiaszimmermann.crypto;

import java.io.File;
import java.util.List;

import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Mnemonic;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;
import org.matthiaszimmermann.crypto.utility.FileUtility;
import org.matthiaszimmermann.crypto.utility.QrCodeUtility;
import org.matthiaszimmermann.crypto.utility.WalletPageUtility;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

public class Application {

	public static final String COMMAND_NAME = "java -jar bpgw.jar";
	public static final String SWITCH_TECHNOLOGY = "-t";
	public static final String SWITCH_DIRECTORY = "-d";
	public static final String SWITCH_MNEMONIC = "-m";
	public static final String SWITCH_PASS_PHRASE = "-p";
	public static final String SWITCH_VERIFY = "-v";

	public static final String VERIFY_OK = "WALLET VERIFICATION OK";
	public static final String VERIFY_ERROR = "WALLET VERIFICATION ERROR";

	public static final String EXT_HTML = "html";
	public static final String EXT_PNG = "png";

	@Parameter(names = {SWITCH_TECHNOLOGY, "--technology"}, description = "technology: (default = Bitcoin)")
	private String technology = Technology.Bitcoin.name();

	@Parameter(names = {SWITCH_DIRECTORY, "--target-directory"}, description = "target directory for wallet file etc.")
	private String targetDirectory = Wallet.DEFAULT_PATH_TO_DIRECTORY;

	@Parameter(names = {SWITCH_MNEMONIC, "--mnemonic"}, description = "mnemonic sentence for the wallet file")
	private String mnemonic;

	@Parameter(names = {SWITCH_PASS_PHRASE, "--pass-phrase"}, description = "pass phrase for the wallet file")
	private String passPhrase;

	@Parameter(names = {SWITCH_VERIFY, "--verify-wallet-file"}, description = "verify the specified wallet file")
	private String walletFile = null;

	@Parameter(names = {"-s", "--silent"}, description = "silent mode, suppress command line output")
	private boolean silent = false;

	@Parameter(names = {"-h", "--help"}, help = true)
	private boolean help;

	public static void main(String[] args) throws Exception {
		Application app = new Application();
		app.run(args);
	}

	public void run(String [] args) {
		processCommandLine(args);

		if(walletFile == null) {
			createWalletFile();
		}
		else {
			verifyWalletFile();
		}
	}

	public void createWalletFile() {
		log("creating wallet file ...");

		// TODO add command line params to indicate network
		Protocol protocol = ProtocolFactory.getInstance(Technology.get(technology), Network.Production);
		// TODO this default value is different compared to targetdirectory
		List<String> mnemonicWords = mnemonic != null ? Mnemonic.convert(mnemonic) : protocol.generateMnemonicWords();
		Wallet wallet = null;

		try {
			wallet = protocol.createWallet(mnemonicWords, passPhrase);
			wallet.setPathToDirectory(targetDirectory);
		}
		catch(Exception e) {
			throw new CreateWalletFileException(String.format("WALLET CREATION ERROR %s", e.getMessage()));
		}

		writeFiles(wallet);
	}

	private void writeFiles(Wallet wallet) {
		String path = wallet.getPathToDirectory();
		String baseName = wallet.getFileBaseName();

		writeWalletFile(wallet, path, baseName);
		writeHtmlFile(wallet, path, baseName);
		writeQRCodeFile(wallet, path, baseName);
	}

	private void writeWalletFile(Wallet wallet, String path, String baseName) {
		String jsonFile = String.format("%s%s%s", path, File.separator, baseName, Wallet.JSON_FILE_EXTENSION);
		FileUtility.saveToFile(wallet.toString(), jsonFile);
		logWalletInfo(wallet);
		log(String.format("wallet file %s successfully created", jsonFile));
	}

	private void writeHtmlFile(Wallet wallet, String path, String baseName) {
		String html = WalletPageUtility.createHtml(wallet);
		String htmlFile = String.format("%s%s%s.%s", path, File.separator, baseName, EXT_HTML);
		FileUtility.saveToFile(html, htmlFile);
		log("writing html and png output files ...");
	}

	private void writeQRCodeFile(Wallet wallet, String path, String baseName) {
		String pngFile = String.format("%s%s%s.%s", path, File.separator, baseName, EXT_PNG);
		byte [] qrCode = QrCodeUtility.contentToPngBytes(wallet.getAccount().getAddress(), 256);
		FileUtility.saveToFile(qrCode, pngFile);
	}

	public void verifyWalletFile() {
		log("verifying wallet file ...");

		try {
			File file = new File(walletFile);
			JSONObject walletJson = FileUtility.readJsonFile(file);
			Protocol protocol = ProtocolFactory.getInstance(walletJson);
			Wallet wallet = protocol.restoreWallet(walletJson, passPhrase);

			log("wallet verification successful");
			logWalletInfo(wallet);
		} 
		catch(Exception e) {
			throw new VerifyWalletFileException(String.format("WALLET VERIFICATION ERROR %s", e.getMessage()));
		}
	}

	private void logWalletInfo(Wallet wallet) {
		Account account = wallet.getAccount();
		String seed = account.getSecret();
		String address = wallet.getAccount().getAddress();
		String passPhrase = wallet.getPassPhrase();
		log("wallet file: " + wallet.getAbsolutePath());
		log("protocol: " + wallet.getProtocol());
		log("address: " + address);
		log("encrypted: " + (passPhrase != null && passPhrase.length() > 0));
		log("pass phrase: " + passPhrase);		
		log("seed: " + seed);

		String mnemonic = Mnemonic.convert(wallet.getMnemonicWords());
		if(!mnemonic.equals(seed)) {
			log("mnemonic: " + mnemonic);
		}
	}

	private void processCommandLine(String [] args) {
		JCommander cmd = new JCommander(this, args);
		cmd.setProgramName(COMMAND_NAME);

		if(help) {
			cmd.usage();
			System.exit(0);
		}
	}

	private void log(String message) {
		if(!silent) {
			System.out.println(message);
		}
	}
}
