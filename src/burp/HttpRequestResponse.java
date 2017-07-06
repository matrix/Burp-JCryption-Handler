package burp;

public class HttpRequestResponse implements IHttpRequestResponse {

	private IHttpService httpService;

	private String comment;
	private String highlight;

	private byte[] request;
	private byte[] response;

	public HttpRequestResponse(IHttpService ihttpService, byte[] irequest)
	{
		this.httpService = ihttpService;
		this.request = irequest;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public String getHighlight() {
		return highlight;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

	@Override
	public byte[] getRequest() {
		return request;
	}

	@Override
	public byte[] getResponse() {
		return response;
	}

	@Override
	public void setComment(String icomment) {
		this.comment = icomment;
	}

	@Override
	public void setHighlight(String ihighlight) {
		this.highlight = ihighlight;
	}

	@Override
	public void setHttpService(IHttpService ihttpService) {
		this.httpService = ihttpService;
	}

	@Override
	public void setRequest(byte[] irequest) {
		this.request = irequest;
	}

	@Override
	public void setResponse(byte[] iresponse) {
		this.response = iresponse;
	}
}
