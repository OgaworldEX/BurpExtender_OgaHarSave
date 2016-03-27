package har;

public class Params {
    private String name;
    private String value;	//optional
    private String fileName;	//optional
    private String contentType;	//optional
    private String comment;	//optional
    
	public static class Builder{
	    private String name;
	    private String value;
	    private String fileName;
	    private String contentType;
	    private String comment;

        public Builder name(String name){
        	this.name = name;
        	return this;
        }
        public Builder value(String value){
        	this.value = value;
        	return this;
        }
        public Builder fileName(String fileName){
        	this.fileName = fileName;
        	return this;
        }
        public Builder contentType(String contentType){
        	this.contentType = contentType;
        	return this;
        }
        public Builder comment(String comment){
        	this.comment = comment;
        	return this;
        }
        public Params build() {
            if (name == null) {
            	StringBuilder sb = new StringBuilder();
            	sb.append("name=");
            	sb.append(name);
                throw new NullPointerException(new String(sb));
            }
            return new Params(this);
        }
    }
    
    private Params(Builder builder) {
	    this.name = builder.name;
	    this.value = builder.value;
	    this.fileName = builder.fileName;
	    this.contentType = builder.contentType;
	    this.comment = builder.comment;
    }
    
	public String getName() {
		return name;
	}
	public String getValue() {
		return value;
	}
	public String getFileName() {
		return fileName;
	}
	public String getContentType() {
		return contentType;
	}
	public String getComment() {
		return comment;
	}
}
