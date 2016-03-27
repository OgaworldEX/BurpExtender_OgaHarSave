package har;

public class Headers {
    private String name;
    private String value;
    private String comment;
    
	public static class Builder{
		private String name;
		private String value;
		private String comment;

        public Builder name(String name){
        	this.name = name;
        	return this;
        }
        public Builder value(String value){
        	this.value = value;
        	return this;
        }
        public Builder comment(String comment){
        	this.comment = comment;
        	return this;
        }
        public Headers build() {
            if (name == null || value == null) {
            	StringBuilder sb = new StringBuilder();
            	sb.append("name=");
            	sb.append(name);
            	sb.append(" value=");
            	sb.append(value);
                throw new NullPointerException(new String(sb));
            }
            return new Headers(this);
        }
    }
    
    private Headers(Builder builder) {
        this.name = builder.name;
        this.value = builder.value;
        this.comment = builder.comment;
    }

	public String getName() {
		return name;
	}

	public String getValue() {
		return value;
	}

	public String getComment() {
		return comment;
	}
    
    
}
