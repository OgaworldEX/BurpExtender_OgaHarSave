package har;

public class Cookies {
    private String name;
    private String value;
    private String path;
    private String domain;
    private String expires;
    private Boolean httpOnly;
    private Boolean secure;
    private String comment;

    public static class Builder {
        private String name;
        private String value;
        private String path;
        private String domain;
        private String expires;
        private Boolean httpOnly;
        private Boolean secure;
        private String comment;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder value(String value) {
            this.value = value;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder domain(String domain) {
            this.domain = domain;
            return this;
        }

        public Builder expires(String expires) {
            this.expires = expires;
            return this;
        }

        public Builder httpOnly(Boolean httpOnly) {
            this.httpOnly = httpOnly;
            return this;
        }

        public Builder secure(Boolean secure) {
            this.secure = secure;
            return this;
        }

        public Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        public Cookies build() {
            if (name == null || value == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("name=");
                sb.append(name);
                sb.append(" value=");
                sb.append(value);
                throw new NullPointerException(new String(sb));
            }
            return new Cookies(this);
        }
    }

    private Cookies(Builder builder) {
        this.name = builder.name;
        this.value = builder.value;
        this.path = builder.path;
        this.domain = builder.domain;
        this.expires = builder.expires;
        this.httpOnly = builder.httpOnly;
        this.secure = builder.secure;
        this.comment = builder.comment;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getPath() {
        return path;
    }

    public String getDomain() {
        return domain;
    }

    public String getExpires() {
        return expires;
    }

    public Boolean getHttpOnly() {
        return httpOnly;
    }

    public Boolean getSecure() {
        return secure;
    }

    public String getComment() {
        return comment;
    }

}
