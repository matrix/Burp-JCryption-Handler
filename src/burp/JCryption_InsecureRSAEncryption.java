package burp;

import java.net.URL;

public class JCryption_InsecureRSAEncryption implements IScanIssue {

	private URL url;
	private IHttpService httpService;
	private IHttpRequestResponse[] httpRequestResponses;
	private String RSAPublicKeyEncoded;

	private final String issueName = "Insecure Implementation of RSA Encryption (jCryption v1.x)";
	private final String severity = "Medium";
	private String confidence;

	private final String issueBackground =
			"Security advisory : <a href='http://www.securityfocus.com/archive/1/520683'>http://www.securityfocus.com/archive/1/520683</a>";

	private String issueDetail =
			"It was possible detect the usage of jCryption v1.x JavaScript library.<br>" +
			"The library has known security issues.<br>";

	private final String remediationDetail =
			"It is recommended to upgrade the jCryption JavaScript library to the lastest version available";

	private final String remediationBackground =
			"Library version releases : <a href='https://github.com/HazAT/jCryption/releases'>https://github.com/HazAT/jCryption/releases</a>";

	public JCryption_InsecureRSAEncryption(IHttpRequestResponse[] baseRequestResponse, IHttpService ihttpService, URL iurl, boolean hashMatched)
	{
		this.httpRequestResponses = baseRequestResponse;
		this.httpService = ihttpService;
		this.url = iurl;
		this.confidence = (!hashMatched) ? "Tentative" : "Certain";
	}

	public JCryption_InsecureRSAEncryption(IHttpRequestResponse[] ihttpRequestResponses, IHttpService ihttpService, URL iurl, String iRSAPublicKeyEncoded)
	{
		this.httpRequestResponses = ihttpRequestResponses;
		this.httpService = ihttpService;
		this.url = iurl;
		this.RSAPublicKeyEncoded = iRSAPublicKeyEncoded;
		this.confidence = "Certain";
		this.issueDetail += "<br>RSA Public Key:<br>[[<br>" + RSAPublicKeyEncoded.replaceAll("\n", "<br>") + "<br>]]<br>";
	}

	@Override
	public String getConfidence() {
		return confidence;
	}

	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return issueName;
	}

	@Override
	public int getIssueType() {
		return 0x08000000; // Extension generated issue
	}

	@Override
	public String getSeverity() {
		return severity;
	}

	@Override
	public String getIssueBackground() {
		return issueBackground;
	}

	@Override
	public String getRemediationBackground() {
		return remediationBackground;
	}

	@Override
	public String getIssueDetail() {
		return issueDetail;
	}

	@Override
	public String getRemediationDetail() {
		return remediationDetail;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpRequestResponses;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}
}
