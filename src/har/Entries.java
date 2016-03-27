package har;

public class Entries {
	private String pageref;
	private String startedDateTime;
	private int time;
	private Request request;
	private Response response;
	private Cache cache;
	private Timings timings;
	private String serverIPAddress;
	private String connection;
	private String comment;
	
	public static class Builder{
		private String pageref;
		private String startedDateTime;
		private int time;
		private Request request;
		private Response response;
		private Cache cache;
		private Timings timings;
		private String serverIPAddress;
		private String connection;
		private String comment;
		
        public Builder pageref(String pageref){
        	this.pageref = pageref;
        	return this;
        }
        public Builder startedDateTime(String startedDateTime){
        	this.startedDateTime = startedDateTime;
        	return this;
        }
        public Builder time(int time){
        	this.time = time;
        	return this;
        }
        public Builder request(Request request){
        	this.request = request;
        	return this;
        }
        public Builder response(Response response){
        	this.response = response;
        	return this;
        }
        public Builder cache(Cache cache){
        	this.cache = cache;
        	return this;
        }
        public Builder timings(Timings timings){
        	this.timings = timings;
        	return this;
        }
        public Builder serverIPAddress(String serverIPAddress){
        	this.serverIPAddress = serverIPAddress;
        	return this;
        }
        public Builder connection(String connection){
        	this.connection = connection;
        	return this;
        }
        public Builder comment(String comment){
        	this.comment = comment;
        	return this;
        }
        public Entries build() {
            if (startedDateTime == null || request == null ||
            	response == null || cache == null) {
                throw new NullPointerException();
            }
            return new Entries(this);
        }
	}
	
    private Entries (Builder builder) {
        this.pageref = builder.pageref;
        this.startedDateTime = builder.startedDateTime;
        this.time = builder.time;
        this.request = builder.request;
        this.response = builder.response;
        this.cache = builder.cache;
        this.timings = builder.timings;
        this.serverIPAddress = builder.serverIPAddress;
        this.connection = builder.connection;
        this.comment = builder.comment;
    }

	public String getPageref() {
		return pageref;
	}

	public String getStartedDateTime() {
		return startedDateTime;
	}

	public int getTime() {
		return time;
	}

	public Request getRequest() {
		return request;
	}

	public Response getResponse() {
		return response;
	}

	public Cache getCache() {
		return cache;
	}

	public Timings getTimings() {
		return timings;
	}

	public String getServerIPAddress() {
		return serverIPAddress;
	}

	public String getConnection() {
		return connection;
	}

	public String getComment() {
		return comment;
	} 
}
