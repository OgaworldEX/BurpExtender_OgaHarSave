package har;

import java.util.List;

public class Request {
	private String method;
	private String url;
	private String httpVersion;
	private List<Cookies> cookies;
	private List<Headers> headers;
	private List<QueryString> queryString;
	private PostData postData;	//optional
	private int headersSize;
	private int bodySize;
	private String comment;	//optional
	
	public static class Builder{
		private String method;
		private String url;
		private String httpVersion;
		private List<Cookies> cookies;
		private List<Headers> headers;
		private List<QueryString> queryString;
		private PostData postData;
		private int headersSize;
		private int bodySize;
		private String comment;
		
		public Builder method(String method){
			this.method = method;
			return this;
		}
		public Builder url(String url){
			this.url = url;
			return this;
		}		
		public Builder httpVersion(String httpVersion){
			this.httpVersion = httpVersion;
			return this;
		}
		public Builder cookies(List<Cookies> cookieList){
			this.cookies = cookieList;
			return this;
		}
		public Builder headers(List<Headers> headers){
			this.headers = headers;
			return this;
		}
		public Builder queryString(List<QueryString> queryString){
			this.queryString = queryString;
			return this;
		}
		public Builder postData(PostData postData){
			this.postData = postData;
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
		
		public Request build(){
			if(method == null || 
				url == null ||
				httpVersion == null || 
				cookies == null ||
				headers == null || 
				queryString == null){
            	
				StringBuilder sb = new StringBuilder();
            	sb.append("method=");
            	sb.append(method);
            	sb.append(" url=");
            	sb.append(url);
            	sb.append(" httpVersion=");
            	sb.append(httpVersion);
            	sb.append(" cookies=");
            	sb.append(cookies);
            	sb.append(" headers=");
            	sb.append(headers);
            	sb.append(" queryString=");
            	sb.append(queryString);
                throw new NullPointerException(new String(sb));
			}
			return new Request(this);
		}
	}
	
	private Request(Builder builder){
		this.method = builder.method;
		this.url = builder.url;
		this.httpVersion = builder.httpVersion;
		this.cookies = builder.cookies;
		this.headers = builder.headers;
		this.queryString = builder.queryString;
		this.postData = builder.postData;
		this.headersSize = builder.headersSize;
		this.bodySize = builder.bodySize;
		this.comment = builder.comment;
	}

	public String getMethod() {
		return method;
	}

	public String getUrl() {
		return url;
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

	public List<QueryString> getQueryString() {
		return queryString;
	}

	public PostData getPostData() {
		return postData;
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
