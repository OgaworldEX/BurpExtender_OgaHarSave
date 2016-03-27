package har;

public class Cache {
    private BeforeRequest beforeRequest;
    private AfterRequest afterRequest;
    private String comment;

    public static class Builder {
        private BeforeRequest beforeRequest;
        private AfterRequest afterRequest;
        private String comment;

        public Builder beforeRequest(BeforeRequest beforeRequest) {
            this.beforeRequest = beforeRequest;
            return this;
        }

        public Builder afterRequest(AfterRequest afterRequest) {
            this.afterRequest = afterRequest;
            return this;
        }

        public Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        public Cache build() {
            return new Cache(this);
        }
    }

    private Cache(Builder builder) {
        this.beforeRequest = builder.beforeRequest;
        this.afterRequest = builder.afterRequest;
        this.comment = builder.comment;
    }

    public BeforeRequest getBeforeRequest() {
        return beforeRequest;
    }

    public AfterRequest getAfterRequest() {
        return afterRequest;
    }

    public String getComment() {
        return comment;
    }
}
