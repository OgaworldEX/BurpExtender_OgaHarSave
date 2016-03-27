package har;

public class Browser {
    private String name;
    private String version;
    private String comment;

    public static class Builder {
        private String name;
        private String version;
        private String comment;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder version(String version) {
            this.version = version;
            return this;
        }

        public Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        public Browser build() {
            if (name == null || version == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("name=");
                sb.append(name);
                sb.append(" version=");
                sb.append(version);
                throw new NullPointerException(new String(sb));

            }
            return new Browser(this);
        }
    }

    private Browser(Builder builder) {
        this.name = builder.name;
        this.version = builder.version;
        this.comment = builder.comment;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public String getComment() {
        return comment;
    }
}
