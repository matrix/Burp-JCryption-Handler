package burp;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController, IMessageEditorTabFactory, IContextMenuFactory, IScannerInsertionPointProvider, IProxyListener, IExtensionStateListener {

	private static final long serialVersionUID = 1L;

	public static String EXTENSION_NAME    = "JCryption Handler";
	public static String EXTENSION_VERSION = "1.1";
	public static String EXTENSION_AUTHOR  = "Gabriele 'matrix' Gristina";
	public static String EXTENSION_URL     = "https://www.github.com/matrix/Burp-JCryption-Handler";
	public static String EXTENSION_IMG     = "/img/matrix_systemFailure.gif";

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private IHttpRequestResponse currentlyDisplayedItem;
	private static final List<LogEntry> log = new ArrayList<LogEntry>();
	private Map<Integer,Integer> refs = new HashMap<>();

	private JTabbedPane mainTab;
	private PreferencesPane preferencesPane;

	private static byte[] mainPassphrase = "".getBytes();
	private static String mainParameter = "jCryption";
	private static List<IParameter> currentSession = null;

	public boolean isBase64(String s)
	{
		Pattern p = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
		return p.matcher(s).matches();
	}

	public static String byteArrayToHex(byte[] a)
	{
		StringBuilder sb = new StringBuilder(a.length * 2);
		for(byte b: a) sb.append(String.format("%02x", b));
		return sb.toString();
	}

	// mainPassphrase get/set

	public static byte[] getPassphrase()
	{
		return mainPassphrase;
	}

	public static void setPassphrase(byte[] p)
	{
		mainPassphrase = p;
	}

	public byte[] getCurrentPassphrase(String dataHash)
	{
		List<LogEntry> r = log.stream().filter(item -> item.dataHash.equals(dataHash)).collect(Collectors.toList());

		return (r.size() > 0 && r.get(0).passphrase.length() > 0) ? r.get(0).passphrase.getBytes() : mainPassphrase;
	}

	// mainParameter get/set

	public static String getParameter()
	{
		return mainParameter;
	}

	public static void setParameter(String p)
	{
		mainParameter = p;
	}

	// currentSession get/set

	public static List<IParameter> getCurrentSession()
	{
		return currentSession;
	}

	public static void setCurrentSession(List<IParameter> c)
	{
		currentSession = c;
	}

	// IBurpExtender

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks icallbacks) {
		this.callbacks = icallbacks;
		this.helpers = callbacks.getHelpers();

		callbacks.setExtensionName(EXTENSION_NAME);

		callbacks.registerScannerInsertionPointProvider(this);
		callbacks.registerMessageEditorTabFactory(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerProxyListener(this);
		callbacks.registerExtensionStateListener(this);

		// if found, restore extension settings
		String lastParameter = callbacks.loadExtensionSetting("JCryption_lastParameter");
		if (lastParameter != null && lastParameter.length() > 0) setParameter(lastParameter);
		String lastPassphrase = callbacks.loadExtensionSetting("JCryption_lastPassphrase");
		if (lastPassphrase != null && lastPassphrase.length() > 0) setPassphrase(helpers.stringToBytes(lastPassphrase));

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

				preferencesPane = new PreferencesPane(callbacks);
				AboutPane aboutPane = new AboutPane();

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
		return 9;
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
				return "Comment";
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
				return logEntry.time;
			case 8:
				return logEntry.comment;
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
			return isRequest && helpers.getRequestParameter(content, mainParameter) != null && preferencesPane.getPluginStatus() == true;
		}

		@Override
		public void setMessage(byte[] content, boolean isRequest) {

			txtInput.setText(null);
			txtInput.setEditable(false);

			if (content != null)
			{
				IParameter parameter = helpers.getRequestParameter(content, mainParameter);
				String urlDecoded = helpers.urlDecode(parameter.getValue());
				if (isBase64(urlDecoded))
				{
					byte[] ciphertext = helpers.base64Decode(urlDecoded);
					currentPassphrase = getCurrentPassphrase(byteArrayToHex(JCryption.getMD5(ciphertext)));

					if (currentPassphrase != null && currentPassphrase.length > 0)
					{
						currentParamType = parameter.getType();
						byte[] decrypted = JCryption.decrypt(currentPassphrase, ciphertext);

						txtInput.setText(decrypted);
						txtInput.setEditable(editable);
					}
				}
			}

			currentMessage = content;
		}

		@Override
		public byte[] getMessage() {
			if (txtInput.isTextModified())
			{
				byte[] text = txtInput.getText();

				if (currentPassphrase != null)
				{
					byte[] encrypted = JCryption.encrypt(currentPassphrase, new String(text));
					String input = helpers.urlEncode(helpers.base64Encode(encrypted));
					return helpers.updateParameter(currentMessage, helpers.buildParameter(mainParameter, input, currentParamType));
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

					List<IParameter> c = getCurrentSession();
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
						byte[] currentPassphrase = getCurrentPassphrase(byteArrayToHex(JCryption.getMD5(ciphertext)));
						byte[] decrypted = JCryption.decrypt(currentPassphrase, ciphertext);

						// encrypt with mainPassphrase
						byte[] encrypt = JCryption.encrypt(mainPassphrase, new String(decrypted));

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

					List<IParameter> c = getCurrentSession();
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
						byte[] currentPassphrase = getCurrentPassphrase(byteArrayToHex(JCryption.getMD5(ciphertext)));
						byte[] decrypted = JCryption.decrypt(currentPassphrase, ciphertext);

						// encrypt with mainPassphrase
						byte[] encrypt = JCryption.encrypt(mainPassphrase, new String(decrypted));

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

		if (preferencesPane.getPluginStatus())
		{
			IHttpRequestResponse messageInfo = message.getMessageInfo();

			if (messageIsRequest)
			{
				IParameter d = helpers.getRequestParameter(messageInfo.getRequest(), mainParameter);
				if (d != null)
				{
					String urlDecoded = helpers.urlDecode(d.getValue());

					if (isBase64(urlDecoded))
					{
						synchronized(log)
						{
							int row = log.size();
							IHttpRequestResponsePersisted irequestResponse = callbacks.saveBuffersToTempFiles(messageInfo);
							IRequestInfo irequestInfo = helpers.analyzeRequest(irequestResponse);
							int ref = message.getMessageReference();

							log.add(new LogEntry(irequestResponse, irequestInfo, helpers.base64Decode(urlDecoded), helpers.bytesToString(mainPassphrase)));
							fireTableRowsInserted(row, row);

							refs.put(ref, row);

							List<IParameter> c = new ArrayList<IParameter>();
							List<IParameter> requestParams = irequestInfo.getParameters();

							for (IParameter parameter : requestParams)
							{
								if (parameter.getType() != IParameter.PARAM_COOKIE) continue;
								c.add(parameter);
							}

							if (c.size() > 0) setCurrentSession(c);
						}
					}
				}
				else
				{
					IHttpService httpService = messageInfo.getHttpService();

					if (httpService.getHost().equals("localhost") && httpService.getPort() == 1337)
					{
						IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
						URL url = requestInfo.getUrl();
						String p = url.getFile().substring(4);
						mainPassphrase = helpers.stringToBytes(p);
						callbacks.saveExtensionSetting("JCryption_lastPassphrase", p);
						preferencesPane.setPassphrase(p);
						message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
					}
				}
			}
			else // processing HTTP Responses
			{
				int ref = message.getMessageReference();
				if (refs.containsKey(ref))
				{
					synchronized(log)
					{
						int row = refs.get(ref);
						LogEntry r = log.get(row);
						if (r != null)
						{
							IHttpRequestResponsePersisted irequestResponse = callbacks.saveBuffersToTempFiles(messageInfo);
							r.response = irequestResponse.getResponse();
							log.set(row, r);
							fireTableRowsUpdated(row, row);
						}
						refs.remove(ref);
					}
				}
				else
				{
					IResponseInfo x = helpers.analyzeResponse(messageInfo.getResponse());

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
						String match = new String("success.call(this, AESEncryptionKey);");
						String replace = new String("setTimeout(function(){ success.call(this, AESEncryptionKey); }, 888); var x = new XMLHttpRequest(); x.open(\"GET\", \"https://localhost:1337/?p=\"+AESEncryptionKey, true); x.send();");
						String response = new String(messageInfo.getResponse());

						if (response.contains(match) && !response.contains(replace))
						{
							String r = response.replaceFirst(Pattern.quote(match), replace);
							int bodyOffset = x.getBodyOffset();
							byte[] res = r.substring(bodyOffset).getBytes();
							message.getMessageInfo().setResponse(helpers.buildHttpMessage(hdr, res));
							message.getMessageInfo().setComment("Hooked by " + EXTENSION_NAME);
							message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
						}
					}
				}
			}
		}
	}

	// IScannerInsertionPointProvider

	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {

		if (preferencesPane.getPluginStatus() == false) return null;

		byte[] req = baseRequestResponse.getRequest();

		IParameter dataParameter = helpers.getRequestParameter(req, mainParameter);

		if (dataParameter == null || mainPassphrase == null)
		{
			return null;
		}

		String urlDecoded = helpers.urlDecode(dataParameter.getValue());
		if (!isBase64(urlDecoded)) return null;

		// if the parameter is present, add custom insertion points for it
		List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();

		byte[] decrypted = JCryption.decrypt(mainPassphrase, helpers.base64Decode(urlDecoded));

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

			insertionPoints.add(new InsertionPoint(req, param, parameter));
		}

		return insertionPoints;
	}

	// IScannerInsertionPoint

	class InsertionPoint implements IScannerInsertionPoint
	{
		private byte[] baseRequest;
		private String insertionPointPrefix;
		private String baseValue;
		private String insertionPointSuffix;
		private byte currentParamType;

		InsertionPoint(byte[] baseRequest, String dataParameter, IParameter parameter)
		{
			this.baseRequest = baseRequest;
			this.currentParamType = parameter.getType();

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
			String input = insertionPointPrefix + helpers.bytesToString(payload) + insertionPointSuffix;

			byte[] p = getPassphrase();
			String par = getParameter();

			if (p != null)
			{
				byte[] encrypted = JCryption.encrypt(p,input);
				input = helpers.urlEncode(helpers.base64Encode(encrypted));
				return helpers.updateParameter(baseRequest, helpers.buildParameter(par, input, currentParamType));
			}

			return null;
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
		String tmp1 = getParameter();
		if (tmp1 != null && tmp1.length() > 0) callbacks.saveExtensionSetting("JCryption_lastParameter", tmp1);
		String tmp2 = helpers.bytesToString(getPassphrase());
		if (tmp2 != null && tmp2.length() > 0) callbacks.saveExtensionSetting("JCryption_lastPassphrase", tmp2);
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

	// class to hold details of each log entry

	private static class LogEntry
	{
		final IHttpRequestResponsePersisted requestResponse;
		final IRequestInfo requestInfo;
		byte[] response;

		final String host;
		final String method;
		final URL url;
		final byte[] params;
		final String cookie;
		final String time;
		final String comment;
		final String passphrase;
		final String dataHash;

		public LogEntry(IHttpRequestResponsePersisted irequestResponse, IRequestInfo irequestInfo, byte[] ciphertext, String passphrase)
		{
			this.requestResponse = irequestResponse;
			this.requestInfo = irequestInfo;

			this.host = requestResponse.getHttpService().getHost();
			this.method = requestInfo.getMethod();
			this.url = requestInfo.getUrl();
			this.params = (passphrase.getBytes().length > 0) ? JCryption.decrypt(passphrase.getBytes(), ciphertext) : "".getBytes();

			List<IParameter> requestParams = requestInfo.getParameters();

			String tmpCookie = "";
			for (IParameter parameter : requestParams)
			{
				if (parameter.getType() != IParameter.PARAM_COOKIE) continue;
				tmpCookie += parameter.getName() + "=" + parameter.getValue() + "; ";
			}

			this.cookie = tmpCookie;
			this.time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
			this.comment = requestResponse.getComment();
			this.passphrase = passphrase;
			this.dataHash = byteArrayToHex(JCryption.getMD5(ciphertext));
		}
	}

	// crypt utils

	private static class JCryption
	{
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
			try
			{
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				SecretKeySpec aKey = new SecretKeySpec(key, "AES");
				IvParameterSpec aIV = new IvParameterSpec(iv);
				cipher.init((mode == 0) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, aKey, aIV);
				return cipher.doFinal(data);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new RuntimeException(e);
			}
			catch (Exception e)
			{
				throw new RuntimeException(e);
			}
		}

		public static byte[] decrypt(byte[] password, byte[] ciphertext)
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

	   public static byte[] encrypt(byte[] password, String plaintext)
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
			byte[] pt  = plaintext.getBytes();
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
