package har;

public class Har {
	private Log log;
	
	public static class Builder{
		private Log log;
		
		public Builder(Log log){
			this.log = log;
		}
		
		public Builder log(Log log){
			this.log = log;
			return this;
		}
		
		public Har build(){
			if(log == null){
            	StringBuilder sb = new StringBuilder();
            	sb.append("log=");
            	sb.append(log);
                throw new NullPointerException(new String(sb));
			}
			return new Har(this);
		}
	}
	
	private Har(Builder builder){
		this.log = builder.log;
	}

	public Log getLog() {
		return log;
	}
}
