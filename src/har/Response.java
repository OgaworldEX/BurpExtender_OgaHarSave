package har;

import java.util.List;

public class Response {
	private int status;
	private String statusText;
	private String httpVersion;
	private List<Cookies> cookies;
	private List<Headers> headers;
	private Content content;
	private String redirectURL;
	private int headersSize;
	private int bodySize;
	private String comment;	//optional
	
	public static class Builder{
		private int status;
		private String statusText;
		private String httpVersion;
		private List<Cookies> cookies;
		private List<Headers> headers;
		private Content content;
		private String redirectURL;
		private int headersSize;
		private int bodySize;
		private String comment;
		
		public Builder status(int status){
			this.status = status;
			return this;
		}
		public Builder statusText(String statusText){
			this.statusText = statusText;
			return this;
		}		
		public Builder httpVersion(String httpVersion){
			this.httpVersion = httpVersion;
			return this;
		}
		public Builder cookies(List<Cookies> cookies){
			this.cookies = cookies;
			return this;
		}
		public Builder headers(List<Headers> headerList){
			this.headers = headerList;
			return this;
		}
		public Builder content(Content content){
			this.content = content;
			return this;
		}
		public Builder redirectURL(String redirectURL){
			this.redirectURL = redirectURL;
			return this;
		}		
		public Builder headersSize(int headersSize){
			this.headersSize = headersSize;
			return this;
		}
		public Builder bodySize(int bodySize){
			this.bodySize = bodySize;
			return this;
		}
		public Builder comment(String comment){
			this.comment = comment;
			return this;
		}
		
		public Response build(){
			if( statusText == null ||
				httpVersion == null || 
				cookies == null ||
				headers == null || 
				content == null || 
				redirectURL == null){
				throw new NullPointerException(); 
			}
			return new Response(this);
		}
	}
	
	private Response(Builder builder){
		this.status = builder.status;
		this.statusText = builder.statusText;
		this.httpVersion = builder.httpVersion;
		this.cookies = builder.cookies;
		this.headers = builder.headers;
		this.content = builder.content;
		this.redirectURL = builder.redirectURL;
		this.headersSize = builder.headersSize;
		this.bodySize = builder.bodySize;
		this.comment = builder.comment;
	}

	public int getStatus() {
		return status;
	}

	public String getStatusText() {
		return statusText;
	}

	public String getHttpVersion() {
		return httpVersion;
	}

	public List<Cookies> getCookies() {
		return cookies;
	}

	public List<Headers> getHeaders() {
		return headers;
	}

	public Content getContent() {
		return content;
	}

	public String getRedirectURL() {
		return redirectURL;
	}

	public int getHeadersSize() {
		return headersSize;
	}

	public int getBodySize() {
		return bodySize;
	}

	public String getComment() {
		return comment;
	}

}
