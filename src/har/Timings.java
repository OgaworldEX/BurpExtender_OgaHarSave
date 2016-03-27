package har;

public class Timings {
    private String blocked;
    private int dns;
    private int connect;
    private int send;
    private int wait;
    private int receive;
    private int ssl;
    private String comment;

    public static class Builder {
        private String blocked;
        private int dns;
        private int connect;
        private int send;
        private int wait;
        private int receive;
        private int ssl;
        private String comment;

        public Builder blocked(String blocked) {
            this.blocked = blocked;
            return this;
        }

        public Builder dns(int dns) {
            this.dns = dns;
            return this;
        }

        public Builder connect(int connect) {
            this.connect = connect;
            return this;
        }

        public Builder send(int send) {
            this.send = send;
            return this;
        }

        public Builder wait(int wait) {
            this.wait = wait;
            return this;
        }

        public Builder receive(int receive) {
            this.receive = receive;
            return this;
        }

        public Builder ssl(int ssl) {
            this.ssl = ssl;
            return this;
        }

        public Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        public Timings build() {
            // no check
            return new Timings(this);
        }
    }

    private Timings(Builder builder) {
        this.blocked = builder.blocked;
        this.dns = builder.dns;
        this.connect = builder.connect;
        this.send = builder.send;
        this.wait = builder.wait;
        this.receive = builder.receive;
        this.ssl = builder.ssl;
        this.comment = builder.comment;
    }

    public String getBlocked() {
        return blocked;
    }

    public int getDns() {
        return dns;
    }

    public int getConnect() {
        return connect;
    }

    public int getSend() {
        return send;
    }

    public int getWait() {
        return wait;
    }

    public int getReceive() {
        return receive;
    }

    public int getSsl() {
        return ssl;
    }

    public String getComment() {
        return comment;
    }

}
