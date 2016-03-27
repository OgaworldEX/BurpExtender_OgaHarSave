package har;

public class AfterRequest {
    private String expires;
    private String lastAccess;
    private String eTag;
    private int hitCount;
    private String comment;

    public static class Builder {
        private String expires;
        private String lastAccess;
        private String eTag;
        private int hitCount;
        private String comment;

        public Builder expires(String expires) {
            this.expires = expires;
            return this;
        }

        public Builder lastAccess(String lastAccess) {
            this.lastAccess = lastAccess;
            return this;
        }

        public Builder eTag(String eTag) {
            this.eTag = eTag;
            return this;
        }

        public Builder hitCount(int hitCount) {
            this.hitCount = hitCount;
            return this;
        }

        public Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        public AfterRequest build() {
            if (lastAccess == null || eTag == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("lastAccess=");
                sb.append(lastAccess);
                sb.append(" eTag=");
                sb.append(eTag);
                throw new NullPointerException();
            }
            return new AfterRequest(this);
        }
    }

    private AfterRequest(Builder builder) {
        this.expires = builder.expires;
        this.lastAccess = builder.lastAccess;
        this.eTag = builder.eTag;
        this.hitCount = builder.hitCount;
        this.comment = builder.comment;
    }

    public String getExpires() {
        return expires;
    }

    public String getLastAccess() {
        return lastAccess;
    }

    public String geteTag() {
        return eTag;
    }

    public int getHitCount() {
        return hitCount;
    }

    public String getComment() {
        return comment;
    }
}
