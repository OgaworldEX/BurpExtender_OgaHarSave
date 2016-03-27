package har;

public class Content {
    private int size;
    private int compression;
    private String mimeType;
    private String text;
    private String encoding;
    private String comment;

    public static class Builder {
        private int size;
        private int compression;
        private String mimeType;
        private String text;
        private String encoding;
        private String comment;

        public Builder size(int size) {
            this.size = size;
            return this;
        }

        public Builder compression(int compression) {
            this.compression = compression;
            return this;
        }

        public Builder mimeType(String mimeType) {
            this.mimeType = mimeType;
            return this;
        }

        public Builder text(String text) {
            this.text = text;
            return this;
        }

        public Builder encoding(String encoding) {
            this.encoding = encoding;
            return this;
        }

        public Builder comment(String comment) {
            this.comment = comment;
            return this;
        }

        public Content build() {
            if (mimeType == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("mimeType=");
                sb.append(mimeType);
                throw new NullPointerException(new String(sb));
            }
            return new Content(this);
        }
    }

    private Content(Builder builder) {
        this.size = builder.size;
        this.compression = builder.compression;
        this.mimeType = builder.mimeType;
        this.text = builder.text;
        this.encoding = builder.encoding;
        this.comment = builder.comment;
    }

    public int getSize() {
        return size;
    }

    public int getCompression() {
        return compression;
    }

    public String getMimeType() {
        return mimeType;
    }

    public String getText() {
        return text;
    }

    public String getEncoding() {
        return encoding;
    }

    public String getComment() {
        return comment;
    }
}
