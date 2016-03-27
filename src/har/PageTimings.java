package har;

public class PageTimings {
	private String onContentLoad;
	private String onLoad;
	private String comment;

	public static class Builder{
		private String onContentLoad;
		private String onLoad;
		private String comment;
		
		public Builder onContentLoad(String onContentLoad){
			this.onContentLoad = onContentLoad;
			return this;
		}
		public Builder onLoad(String onLoad){
			this.onLoad = onLoad;
			return this;
		}		
		public Builder comment(String comment){
			this.comment = comment;
			return this;
		}		
		public PageTimings build(){
			return new PageTimings(this);
		}
	}
	
	private PageTimings(Builder builder){
		this.onContentLoad = builder.onContentLoad;
		this.onLoad = builder.onLoad;
		this.comment = builder.comment;
	}
	
	public String getOnContentLoad() {
		return onContentLoad;
	}
	public String getOnLoad() {
		return onLoad;
	}
	public String getComment() {
		return comment;
	}
}
