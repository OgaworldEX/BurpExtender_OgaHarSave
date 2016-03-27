package har;

import java.util.List;

public class PostData {
    private String mimeType;
    private List<Params> params;
    private String text;
    private String comment; //optional
    
    public static class Builder{
        private String mimeType;
        private List<Params> params;
        private String text;
        private String comment;
        
    	public Builder mimeType(String mimeType){
    		this.mimeType = mimeType;
    		return this;
    	}
    	public Builder params(List<Params> params){
    		this.params = params;
    		return this;
    	}
    	public Builder text(String text){
    		this.text = text;
    		return this;
    	}
    	public Builder comment(String comment){
    		this.comment = comment;
    		return this;
    	}
    	
    	public PostData build() {
            if (mimeType == null || 
            	params == null || 
            	text == null) {
            	
            	StringBuilder sb = new StringBuilder();
            	sb.append("mimeType=");
            	sb.append(mimeType);
            	sb.append(" params=");
            	sb.append(params);
            	sb.append(" text=");
            	sb.append(text);
                throw new NullPointerException(new String(sb));
            }
            return new PostData(this);
        }
    }
    
    private PostData(Builder builder){
    	this.mimeType = builder.mimeType;
    	this.params = builder.params;
    	this.text = builder.text;
    	this.comment = builder.comment;
    }

	public String getMimeType() {
		return mimeType;
	}

	public List<Params> getParams() {
		return params;
	}

	public String getText() {
		return text;
	}

	public String getComment() {
		return comment;
	}
}
