package har;

import java.util.List;

public class Log {
	
	private String version;
	private Creator creater;
	private Browser browser;
	private List<Pages> pages;
	private List<Entries> entries;
	private String comment;
	
	public static class Builder{
		private String version;
		private Creator creater;
		private Browser browser;
		private List<Pages> pages;
		private List<Entries> entries;
		private String comment; 
		
		public Builder version(String version){
			this.version = version;
			return this;
		}
		public Builder creator(Creator creater){
			this.creater = creater;
			return this;
		}
		public Builder browser(Browser browser){
			this.browser = browser;
			return this;
		}
		public Builder pages(List<Pages> pagesList){
			this.pages = pagesList;
			return this;
		}
		public Builder entries(List<Entries> entries){
			this.entries = entries;
			return this;
		}
		public Builder comment(String comment){
			this.comment = comment;
			return this;
		}
		public Log build() {
            if (version == null || creater == null || entries == null) {
            	StringBuilder sb = new StringBuilder();
            	sb.append("version=");
            	sb.append(version);
            	sb.append(" creater=");
            	sb.append(creater);
            	sb.append(" entries=");
            	sb.append(entries);
            	throw new NullPointerException(new String(sb));            	
            }
            return new Log(this);
        }
	}
	
    private Log(Builder builder) {
		this.version = builder.version;
		this.creater = builder.creater;
		this.browser = builder.browser;
		this.pages = builder.pages;
		this.entries = builder.entries;
		this.comment = builder.comment;
    }

	public String getVersion() {
		return version;
	}

	public Creator getCreater() {
		return creater;
	}

	public Browser getBrowser() {
		return browser;
	}

	public List<Pages> getPages() {
		return pages;
	}

	public List<Entries> getEntries() {
		return entries;
	}

	public String getComment() {
		return comment;
	}

}
