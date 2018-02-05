package org.matthiaszimmermann.crypto.pwg.iota;

import java.io.File;
import java.util.List;

import org.matthiaszimmermann.crypto.common.FileUtility;
import org.matthiaszimmermann.crypto.common.Mnemonic;
import org.matthiaszimmermann.crypto.common.Network;
import org.matthiaszimmermann.crypto.common.Protocol;
import org.matthiaszimmermann.crypto.common.ProtocolFactory;
import org.matthiaszimmermann.crypto.common.Technology;
import org.matthiaszimmermann.crypto.common.Wallet;
import org.matthiaszimmermann.crypto.common.WalletFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

public class Application {

	public static final String COMMAND_NAME = "java -jar bpgw.jar";
	public static final String SWITCH_DIRECTORY = "-d";
	public static final String SWITCH_MNEMONIC = "-m";
	public static final String SWITCH_PASS_PHRASE = "-p";
	public static final String SWITCH_VERIFY = "-v";

	public static final String CREATE_OK = "WALLET CREATION OK";
	public static final String CRATE_ERROR = "WALLET CREATION ERROR";

	public static final String VERIFY_OK = "WALLET VERIFICATION OK";
	public static final String VERIFY_ERROR = "WALLET VERIFICATION ERROR";

	public static final String EXT_HTML = "html";
	public static final String EXT_PNG = "png";

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

	public String run(String [] args) {
		parseCommandLine(args);

		if(walletFile == null) {
			return createWalletFile();
		}
		else {
			return verifyWalletFile();
		}
	}

	public String createWalletFile() {
		log("creating wallet file ...");
		
		List<String> mnemonicWords = mnemonic == null ? null : Mnemonic.convert(mnemonic);
		Protocol protocol = null;
		Wallet wallet = null;

		// TODO add command line params to indicate technology and network
		try {
			protocol = ProtocolFactory.getInstance(Technology.Iota, Network.Production);
			wallet = WalletFactory.getInstance(mnemonicWords, passPhrase, protocol);
			wallet.setPathToDirectory(targetDirectory);
			
			log("mnemonic: " + Mnemonic.convert(wallet.getMnemonicWords()));
			log("seed: " + wallet.getAccount().getSecret());
			log("address: " + wallet.getAccount().getAddress());
			
		}
		catch(Exception e) {
			return String.format("%s %s", CRATE_ERROR, e.getMessage());
		}

		String jsonFile = wallet.getAbsolutePath();
		FileUtility.saveToFile(wallet.toString(), jsonFile);
		log(String.format("wallet file %s successfully created", jsonFile));

		String html = WalletPageUtility.createHtml(wallet);
		byte [] qrCode = QrCodeUtility.contentToPngBytes(wallet.getAccount().getAddress(), 256);

		String path = wallet.getPathToDirectory();
		String baseName = wallet.getFileBaseName();
		String htmlFile = String.format("%s%s%s.%s", path, File.separator, baseName, EXT_HTML);
		String pngFile = String.format("%s%s%s.%s", path, File.separator, baseName, EXT_PNG);

		log("writing html and png output files ...");
		FileUtility.saveToFile(html, htmlFile);
		FileUtility.saveToFile(qrCode, pngFile);

		return String.format("%s %s", CREATE_OK, wallet.getAbsolutePath());
	}

	public String verifyWalletFile() {
		log("verifying wallet file ...");
		
		Protocol protocol = ProtocolFactory.getInstance(Technology.Iota, Network.Production);
		File file = new File(walletFile);
		
		try {
			List<String> mnemonicWords = mnemonic == null ? null : Mnemonic.convert(mnemonic);
			WalletFactory.getInstance(file, mnemonicWords, passPhrase, protocol);
			log("wallet verification successful");
			return VERIFY_OK;
		} 
		catch (Exception e) {
			log("verification failed: " + e.getLocalizedMessage());
			return VERIFY_ERROR + " " + e.getLocalizedMessage();
		}
	}

	private void parseCommandLine(String [] args) {
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
