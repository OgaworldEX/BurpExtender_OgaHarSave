package har;

public class Pages {
    private String startedDateTime;
    private String id;
    private String title;
    private PageTimings pageTimings;
    private String comment;
    
	public static class Builder{
	    private String startedDateTime;
	    private String id;
	    private String title;
	    private PageTimings pageTimings;
	    private String comment;
	    
	    public Builder startedDateTime(String startedDateTime){
			this.startedDateTime = startedDateTime;
			return this;
		}
	    public Builder id(String id){
			this.id = id;
			return this;
		}
	    public Builder title(String title){
			this.title = title;
			return this;
		}
	    public Builder pageTimings(PageTimings pageTimings){
			this.pageTimings = pageTimings;
			return this;
		}
	    public Builder comment(String comment){
			this.comment = comment;
			return this;
	    }
	    public Pages build(){
	    	if (startedDateTime == null || id == null || 
	    		title == null || pageTimings == null){
            	StringBuilder sb = new StringBuilder();
            	sb.append("startedDateTime=");
            	sb.append(startedDateTime);
            	sb.append(" id=");
            	sb.append(id);
            	sb.append(" title=");
            	sb.append(title);
            	sb.append(" pageTimings=");
            	sb.append(pageTimings);
                throw new NullPointerException(new String(sb));
	    		
	    	}
	    	return new Pages(this);
	    }
	}
	
	private Pages(Builder builder){
		this.startedDateTime = builder.startedDateTime;
		this.id = builder.id;
		this.title = builder.title;
		this.pageTimings = builder.pageTimings;
		this.comment = builder.comment;
	}

	public String getStartedDateTime() {
		return startedDateTime;
	}

	public String getId() {
		return id;
	}

	public String getTitle() {
		return title;
	}

	public PageTimings getPageTimings() {
		return pageTimings;
	}

	public String getComment() {
		return comment;
	}
}
