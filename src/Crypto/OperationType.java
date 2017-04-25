package Crypto;

public enum OperationType {
	
        READ("READ"),
        WRITE("WRITE");

        private String type;

        OperationType(String type) {
            this.type = type;
        }

        public String type() {
            return type;
        }
}


